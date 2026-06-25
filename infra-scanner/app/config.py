import os

RABBITMQ_URL  = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
JOBS_EXCHANGE = os.getenv("JOBS_EXCHANGE", "scan_jobs_fanout")
CONSUME_QUEUE = os.getenv("CONSUME_QUEUE", "scan_jobs.infra")   # this service's own queue
PUBLISH_QUEUE = os.getenv("PUBLISH_QUEUE", "scan_results")
PORT          = os.getenv("PORT", "8004")
SERVICE_NAME  = "infra-scanner"

# Project root, mounted read-only into the container (see docker-compose volumes below).
# Checkov scans the IaC files here; Trivy reads docker-compose.yml from here to learn
# which images to scan.
WORKSPACE_PATH = os.getenv("WORKSPACE_PATH", "/workspace")

# Docker Compose v2 names built images "<project>-<service>" (project = the directory name,
# lowercased). Override here if your project name differs. Verify with `docker images`.
COMPOSE_PROJECT_NAME = os.getenv("COMPOSE_PROJECT_NAME", "devsecops-skeleton")