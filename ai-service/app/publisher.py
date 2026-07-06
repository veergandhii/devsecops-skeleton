import json
import logging
import aio_pika
from app.config import AI_RESULTS_EXCHANGE
from app.logging_config import correlation_id_var


async def publish_enriched(channel: aio_pika.Channel, payload: dict):
    # ai-results now has TWO consumers (github-service + results-aggregator, Phase 12), so it's
    # a fanout exchange: declare + publish ONE copy, RabbitMQ duplicates to every bound queue.
    exchange = await channel.declare_exchange(
        AI_RESULTS_EXCHANGE, aio_pika.ExchangeType.FANOUT, durable=True)
    await exchange.publish(
        aio_pika.Message(
            body=json.dumps(payload).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
            headers={"correlation_id": correlation_id_var.get()},   # keep the thread unbroken
        ),
        routing_key="",   # fanout ignores it
    )
    logging.info(f"📤 published enriched results for job {payload.get('job_id')}")