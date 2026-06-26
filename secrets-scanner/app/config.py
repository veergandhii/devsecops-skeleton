import os
# RABBITMQ_URL is injected by docker-compose env_file. The default only applies
# if you run the service outside Docker. "rabbitmq" is the compose service name,
# resolved by Docker's internal DNS.
RABBITMQ_URL  = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
# Fan-out: the webhook publishes each job to this ONE exchange; every scanner binds
# its OWN queue to it, so every scanner receives every job (see "Job Fan-out" above).
JOBS_EXCHANGE = os.getenv("JOBS_EXCHANGE", "scan_jobs_fanout")
CONSUME_QUEUE = os.getenv("CONSUME_QUEUE", "scan_jobs.secrets")  # THIS service's own queue
PUBLISH_QUEUE = os.getenv("PUBLISH_QUEUE", "scan_results")       # all scanners publish here
PORT          = os.getenv("PORT", "8003")                       # unique per service
SERVICE_NAME  = "secrets-scanner"                              # appears in every finding
RESULTS_EXCHANGE = os.getenv("RESULTS_EXCHANGE", "scan_results_fanout")