import os
RABBITMQ_URL = os.getenv("RABBITMQ_URL","amqp://guest:guest@rabbitmq/")
CONSUME_QUEUE=os.getenv("CONSUME_QUEUE","scan_jobs")
PUBLISH_QUEUE=os.getenv("PUBLISH_QUEUE","scan_results")
PORT=os.getenv("PORT","8002")
