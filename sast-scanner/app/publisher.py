import json
import aio_pika
from app.config import RABBITMQ_URL, PUBLISH_QUEUE


async def publish_findings(channel: aio_pika.Channel, job_id: str, findings: list[dict]):
    payload = {
        "job_id":   job_id,
        "findings": findings,
        "count":    len(findings),
    }

    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(payload).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        ),
        routing_key=PUBLISH_QUEUE,
    )
    print(f"📤 Published {len(findings)} findings for job {job_id}")