import aio_pika, json, os

async def publish_message(payload):
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
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT)  # survive broker restart
            await exchange.publish(message, routing_key="")      # fanout ignores routing_key
