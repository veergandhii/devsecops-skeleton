import json, asyncio, aio_pika, logging
from app.config import RABBITMQ_URL, RESULTS_EXCHANGE, CONSUME_QUEUE
from app.models import save_envelope

logger = logging.getLogger(__name__)


async def start_consumer():
    while True:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URL); break
        except Exception as e:
            logger.warning("RabbitMQ not ready: %s", e); await asyncio.sleep(2)

    channel = await connection.channel()
    await channel.set_qos(prefetch_count=1)
    # Bind our own queue to the ai-results fanout exchange (Step 0).
    exchange = await channel.declare_exchange(RESULTS_EXCHANGE, aio_pika.ExchangeType.FANOUT, durable=True)
    queue = await channel.declare_queue(CONSUME_QUEUE, durable=True)
    await queue.bind(exchange)

    async def on_message(message: aio_pika.IncomingMessage):
        async with message.process():
            envelope = json.loads(message.body.decode())
            save_envelope(envelope)
            logger.info("stored run", extra={"job_id": envelope.get("job_id"),
                                              "findings": envelope.get("count", 0)})

    await queue.consume(on_message)
    logger.info("results-aggregator listening on %s", CONSUME_QUEUE)
    await asyncio.Future()