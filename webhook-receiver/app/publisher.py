import json 
import aio_pika
import os

async def publish_message(payload):
    rabbitmq_url = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")  # amqp is advance msging queue protocol
    
    async with await aio_pika.connect_robust(rabbitmq_url) as connection:  # auto-closes cleanly
        async with connection.channel() as channel:                         # auto-closes channel too
            queue = os.getenv("QUEUE_NAME", "scan_jobs")
            await channel.declare_queue(queue, durable=True)
            message_body = json.dumps(payload).encode()
            message = aio_pika.Message(body=message_body)
            await channel.default_exchange.publish(message, routing_key=queue)
    # connection and channel both cleanly closed here 