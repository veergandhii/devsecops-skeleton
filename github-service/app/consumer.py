import json
import logging
import asyncio
import aio_pika

from app.config import RABBITMQ_URL, CONSUME_QUEUE
from app.github_client import post_comment
from app.logging_config import correlation_id_var


async def start_consumer():
    while True:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            break
        except Exception as e:
            print(f"RabbitMQ not ready, retrying in 2s... ({e})")
            await asyncio.sleep(2)

    channel = await connection.channel()
    await channel.set_qos(prefetch_count=1)
    queue = await channel.declare_queue(CONSUME_QUEUE, durable=True)

    async def on_message(message: aio_pika.IncomingMessage):
        async with message.process():
            cid = (message.headers or {}).get("correlation_id", "-")
            correlation_id_var.set(cid)     # tags every log line in this task with the trace

            envelope = json.loads(message.body.decode())
            job_id   = envelope.get("job_id", "unknown")
            logging.info(f"💬 posting PR comment for job {job_id}")
            ok = post_comment(envelope)     # blocking PyGithub call; fine at prefetch=1
            logging.info(f"{'✅' if ok else '⚠️ '} job {job_id}: comment {'posted' if ok else 'skipped'}")

    await queue.consume(on_message)
    logging.info(f"👂 github-service listening on [{CONSUME_QUEUE}]")
    await asyncio.Future()