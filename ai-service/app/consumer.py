import json
import logging
import asyncio
import aio_pika

from app.config import RABBITMQ_URL, RESULTS_EXCHANGE, CONSUME_QUEUE
from app.ai_client import enrich
from app.publisher import publish_enriched
from app.logging_config import correlation_id_var


async def start_consumer():
    # 1. Connect with retry (same as every service)
    while True:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            break
        except Exception as e:
            print(f"RabbitMQ not ready, retrying in 2s... ({e})")
            await asyncio.sleep(2)

    consume_channel = await connection.channel()
    await consume_channel.set_qos(prefetch_count=1)
    publish_channel = await connection.channel()

    # 2. Bind OUR queue to the results fanout exchange (Step 2). We receive a copy of
    #    every result envelope the scanners publish; the orchestrator gets its own copy.
    exchange = await consume_channel.declare_exchange(
        RESULTS_EXCHANGE, aio_pika.ExchangeType.FANOUT, durable=True)
    queue = await consume_channel.declare_queue(CONSUME_QUEUE, durable=True)
    await queue.bind(exchange)

    async def on_message(message: aio_pika.IncomingMessage):
        async with message.process():
            cid = (message.headers or {}).get("correlation_id", "-")
            correlation_id_var.set(cid)     # tags every log line in this task with the trace

            envelope = json.loads(message.body.decode())
            job_id   = envelope.get("job_id", "unknown")
            findings = envelope.get("findings", [])
            logging.info(f"🤖 enriching {len(findings)} finding(s) for job {job_id}")

            # Dedup to protect the free-tier quota: identical findings (same rule_id) get the
            # SAME enrichment, so we call Gemini ONCE per unique rule_id and reuse the result.
            # An infra scan with 170 findings but ~25 distinct CVEs costs ~25 calls, not 170.
            cache: dict[str, dict] = {}
            enriched = []
            for finding in findings:
                key = finding.get("rule_id") or finding.get("description", "")
                if key not in cache:
                    cache[key] = await enrich(finding)   # one API call per unique rule_id
                enriched.append({**finding, "ai": cache[key]})   # reuse, keep original fields
            logging.info(f"   ↳ {len(findings)} finding(s) → {len(cache)} unique rule_id(s) = "
                         f"{len(cache)} Gemini call(s)")

            # Re-publish the SAME envelope shape, now with AI-augmented findings.
            await publish_enriched(publish_channel, {
                **envelope,
                "service":  "ai-service",
                "findings": enriched,
            })
            logging.info(f"✅ job {job_id}: enriched and published")

    await queue.consume(on_message)
    logging.info(f"👂 ai-service listening on [{CONSUME_QUEUE}]")
    await asyncio.Future()