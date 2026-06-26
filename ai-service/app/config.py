import os

RABBITMQ_URL    = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
# Results-side fan-out: scanners publish to this exchange; ai-service binds its own queue.
RESULTS_EXCHANGE = os.getenv("RESULTS_EXCHANGE", "scan_results_fanout")
CONSUME_QUEUE    = os.getenv("CONSUME_QUEUE", "scan_results.ai")   # this service's own queue
PUBLISH_QUEUE    = os.getenv("PUBLISH_QUEUE", "ai-results")        # enriched output
PORT             = os.getenv("PORT", "8005")
SERVICE_NAME     = "ai-service"

# ── Gemini API ──────────────────────────────────────────────────────────────
# The key is read from the environment ONLY. Never write it in code or commit it.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")