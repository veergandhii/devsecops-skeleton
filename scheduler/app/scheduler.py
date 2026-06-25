# scheduler/app/scheduler.py - CodeSheriff infra trigger (starts the "scheduled flow")
#
# This unit's ONLY job: on a cron cadence, drop ONE trigger message onto scan_jobs.infra.
# It scans nothing itself. It is the part of "run infra periodically, not on every push"
# that the webhook structurally cannot do: a push can't fire on a clock.
import asyncio
import json
import os
from datetime import datetime, timezone

import aio_pika
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
INFRA_QUEUE = os.getenv("INFRA_QUEUE", "scan_jobs.infra")   # infra-scanner's own queue
INFRA_CRON = os.getenv("INFRA_CRON", "0 2 * * *")           # 02:00 daily (m h dom mon dow)


async def publish_infra_trigger() -> None:
    """Publish one trigger straight to scan_jobs.infra, not to scan_jobs_fanout.

    Bypassing the exchange is the entire point: no push, no fan-out, just the clock."""
    connection = await aio_pika.connect_robust(RABBITMQ_URL)
    async with connection:
        channel = await connection.channel()
        # Declare the SAME durable queue infra-scanner consumes (idempotent if it already exists).
        # Publish via the default exchange with routing_key = queue name.
        await channel.declare_queue(INFRA_QUEUE, durable=True)
        payload = {
            "job_id":   f"infra-{datetime.now(timezone.utc):%Y%m%d-%H%M}",
            "trigger":  "scheduled",   # provenance: a clock started this, not a commit
            "language": "n/a",
            "code":     "",            # infra-scanner ignores code (Design decision 1)
        }
        await channel.default_exchange.publish(
            aio_pika.Message(
                body=json.dumps(payload).encode(),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            ),
            routing_key=INFRA_QUEUE,
        )
        print(f"published scheduled infra trigger {payload['job_id']} -> {INFRA_QUEUE}")


async def main() -> None:
    scheduler = AsyncIOScheduler()
    # from_crontab parses a standard 5-field cron string. Swap INFRA_CRON in .env to retune the
    # cadence (e.g. "0 */6 * * *" = every 6 hours) with no code change.
    scheduler.add_job(publish_infra_trigger, CronTrigger.from_crontab(INFRA_CRON))
    scheduler.start()
    print(f"infra scheduler up - cadence '{INFRA_CRON}' -> {INFRA_QUEUE}")
    await asyncio.Future()   # park forever; APScheduler fires publish_infra_trigger in the bg


if __name__ == "__main__":
    asyncio.run(main())
