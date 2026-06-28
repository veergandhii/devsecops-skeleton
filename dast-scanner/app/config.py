import os

RABBITMQ_URL     = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
JOBS_EXCHANGE    = os.getenv("JOBS_EXCHANGE", "scan_jobs_fanout")
CONSUME_QUEUE    = os.getenv("CONSUME_QUEUE", "scan_jobs.dast")
RESULTS_EXCHANGE = os.getenv("RESULTS_EXCHANGE", "scan_results_fanout")
PORT             = os.getenv("PORT", "8007")
SERVICE_NAME     = "dast-scanner"

# Comma-separated internal URLs to scan. Service names resolve on the compose network.
DAST_TARGETS = os.getenv(
    "DAST_TARGETS",
    "http://webhook-receiver:8000,http://scan-orchestrator:8001",
).split(",")

