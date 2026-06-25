import json
import aio_pika
from datetime import datetime, timezone

from app.config import PUBLISH_QUEUE, SERVICE_NAME


async def publish_findings(channel: aio_pika.Channel, job_id: str, findings: list[dict]):
    # The standardised result envelope every service publishes to scan_results.
    # scan-orchestrator already reads job_id + findings + count; we ADD service +
    # timestamp so downstream (AI, dashboard) can attribute and order findings.
    payload = {
        "job_id":    job_id,
        "service":   SERVICE_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "count":     len(findings),
        "findings":  findings,
    }

    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(payload).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,  # survive broker restart
            content_type="application/json",
        ),
        routing_key=PUBLISH_QUEUE,   # default exchange routes by queue name
    )
    print(f"Published {len(findings)} findings for job {job_id}")
