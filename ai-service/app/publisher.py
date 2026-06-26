import json
import aio_pika
from app.config import PUBLISH_QUEUE


async def publish_enriched(channel: aio_pika.Channel, payload: dict):
    # ai-results currently has ZERO consumers (github-service arrives in Phase 7). A plain
    # durable queue is correct until a SECOND consumer appears — then fan it out, same pattern.
    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(payload).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
        ),
        routing_key=PUBLISH_QUEUE,
    )
    print(f"📤 published enriched results for job {payload.get('job_id')}")