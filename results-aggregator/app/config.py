import os

RABBITMQ_URL    = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
RESULTS_EXCHANGE = os.getenv("AI_RESULTS_EXCHANGE", "ai_results_fanout")
CONSUME_QUEUE    = os.getenv("CONSUME_QUEUE", "ai-results.aggregator")
PORT             = os.getenv("PORT", "8080")
SERVICE_NAME     = "results-aggregator"

# SQLite file on a mounted volume so data survives container restarts.
DB_PATH = os.getenv("DB_PATH", "/data/codesheriff.db")

# Services to health-check on the Services page (name → internal URL).
SERVICES = {
    "webhook-receiver": "http://webhook-receiver:8000/health",
    "scan-orchestrator": "http://scan-orchestrator:8001/health",
    "sast-scanner":     "http://sast-scanner:8002/health",
    "secrets-scanner":  "http://secrets-scanner:8003/health",
    "infra-scanner":    "http://infra-scanner:8004/health",
    "ai-service":       "http://ai-service:8005/health",
    "github-service":   "http://github-service:8006/health",
    "dast-scanner":     "http://dast-scanner:8007/health",
}