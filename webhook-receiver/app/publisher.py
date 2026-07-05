import uuid, aio_pika, json, os, logging
from app.logging_config import correlation_id_var

async def publish_message(payload):
    # This is the ONE place a job is born: mint the correlation_id here and set it on the
    # current task's context so every log line for this request (in this handler and inside
    # this call) is tagged, then ride it along on the message header for every downstream hop.
    correlation_id = str(uuid.uuid4())
    correlation_id_var.set(correlation_id)

    rabbitmq_url = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
    async with await aio_pika.connect_robust(rabbitmq_url) as connection:
        async with connection.channel() as channel:
            exchange_name = os.getenv("JOBS_EXCHANGE", "scan_jobs_fanout")
            # FANOUT: declare the exchange, then publish ONE copy. RabbitMQ duplicates it
            # into every queue bound to this exchange (each scanner binds its own queue).
            exchange = await channel.declare_exchange(
                exchange_name, aio_pika.ExchangeType.FANOUT, durable=True)
            message = aio_pika.Message(
                body=json.dumps(payload).encode(),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,   # survive broker restart
                headers={"correlation_id": correlation_id},
            )
            await exchange.publish(message, routing_key="")      # fanout ignores routing_key
    logging.info(f"published job {payload.get('job_id')} correlation_id={correlation_id}")
