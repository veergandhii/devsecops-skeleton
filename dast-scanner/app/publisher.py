import json, aio_pika
from datetime import datetime, timezone
from app.config import RESULTS_EXCHANGE, SERVICE_NAME   # results fan-out (Phase 6)

async def publish_findings(channel: aio_pika.Channel, job_id: str, findings: list[dict], meta: dict):
    payload = {
        "job_id":    job_id,
        "service":   SERVICE_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "count":     len(findings),
        "findings":  findings,
        "meta":      meta,
    }
    # FANOUT: declare + publish ONE copy; RabbitMQ duplicates to every bound queue.
    exchange = await channel.declare_exchange(
        RESULTS_EXCHANGE, aio_pika.ExchangeType.FANOUT, durable=True)
    await exchange.publish(
        aio_pika.Message(
            body=json.dumps(payload).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
        ),
        routing_key="",   # fanout ignores it
    )
