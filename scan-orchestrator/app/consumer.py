import json
import aio_pika
import os
import asyncio

async def start_consumer():
    rabbitmq_url = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
    queue_name = os.getenv("QUEUE_NAME", "scan_jobs")

    while True:
        try:
            connection = await aio_pika.connect_robust(rabbitmq_url)
            break
        except Exception as e:
            print(f"RabbitMQ not ready, retrying in 2s... ({e})")
            await asyncio.sleep(2)

    channel = await connection.channel()
    await channel.set_qos(prefetch_count=1)
    exchange = await channel.declare_exchange(
    "scan_results_fanout", aio_pika.ExchangeType.FANOUT, durable=True)
    queue = await channel.declare_queue("scan_results.orchestrator", durable=True)
    await queue.bind(exchange)

    async def on_message(message: aio_pika.IncomingMessage):
        async with message.process():
            payload = json.loads(message.body.decode())
            print("Received job:", payload)

    await queue.consume(on_message)  # callback-based, doesn't block the loop
    print("👂 Consumer is now listening for messages...")

    await asyncio.Future()  # keeps the coroutine alive without blocking