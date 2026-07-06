import os

RABBITMQ_URL  = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
# ai-results fan-out (Phase 12): github-service binds its OWN queue to the shared exchange
# so it and results-aggregator each get a copy of every envelope.
AI_RESULTS_EXCHANGE = os.getenv("AI_RESULTS_EXCHANGE", "ai_results_fanout")
CONSUME_QUEUE = os.getenv("CONSUME_QUEUE", "ai-results.github")
PORT          = os.getenv("PORT", "8006")
SERVICE_NAME  = "github-service"

# GitHub token from env ONLY. GITHUB_REPO is a fallback used when a job's meta has no repo
# (handy for manual testing against one fixed repo before Phase 10 wires real webhooks).
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO  = os.getenv("GITHUB_REPO", "") 