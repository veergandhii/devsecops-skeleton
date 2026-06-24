import os
RABBITMQ_URL  = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
JOBS_EXCHANGE = os.getenv("JOBS_EXCHANGE", "scan_jobs_fanout")
CONSUME_QUEUE = os.getenv("CONSUME_QUEUE", "scan_jobs.sast")
PUBLISH_QUEUE = os.getenv("PUBLISH_QUEUE", "scan_results")
PORT          = os.getenv("PORT", "8002")
SERVICE_NAME  = "sast-scanner"