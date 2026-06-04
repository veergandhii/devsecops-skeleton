import json
import asyncio
import aio_pika

from app.config import RABBITMQ_URL, CONSUME_QUEUE
from app.scanner import run_semgrep, run_bandit
from app.publisher import publish_findings


async def start_consumer():
    # ── 1. Connect with retry ────────────────────────────────────────────────
    while True:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            break
        except Exception as e:
            print(f"RabbitMQ not ready, retrying in 2s... ({e})")
            await asyncio.sleep(2)

    # ── 2. Separate channels for consuming and publishing ────────────────────
    consume_channel = await connection.channel()
    await consume_channel.set_qos(prefetch_count=1)
    publish_channel = await connection.channel()

    from app.config import PUBLISH_QUEUE
    queue = await consume_channel.declare_queue(CONSUME_QUEUE, durable=True)
    await publish_channel.declare_queue(PUBLISH_QUEUE, durable=True)

    # ── 3. Message handler ───────────────────────────────────────────────────
    async def on_message(message: aio_pika.IncomingMessage):
        async with message.process():
            payload = json.loads(message.body.decode())
            job_id   = payload.get("job_id", "unknown")
            code     = payload.get("code", "")
            language = payload.get("language", "python")

            print(f"🔍 Scanning job {job_id} ({language})")

            semgrep_findings = run_semgrep(code, language)
            bandit_findings  = run_bandit(code) if language.lower() == "python" else []

            all_findings = semgrep_findings + bandit_findings
            print(f"✅ job {job_id}: {len(all_findings)} finding(s)")

            await publish_findings(publish_channel, job_id, all_findings)

    await queue.consume(on_message)
    print(f"👂 sast-scanner listening on [{CONSUME_QUEUE}]")

    await asyncio.Future()