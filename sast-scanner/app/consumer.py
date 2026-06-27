import json
import asyncio
import aio_pika

from app.config import RABBITMQ_URL, JOBS_EXCHANGE, CONSUME_QUEUE, RESULTS_EXCHANGE
from app.scanner import scan
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

    exchange = await consume_channel.declare_exchange(
        JOBS_EXCHANGE, aio_pika.ExchangeType.FANOUT, durable=True)
    queue = await consume_channel.declare_queue(CONSUME_QUEUE, durable=True)
    await queue.bind(exchange)
    # Results side is also fan-out now: declare the exchange we publish to (the publisher
    # publishes here). NOT a plain `scan_results` queue — that was the pre-fanout leftover.
    await publish_channel.declare_exchange(
        RESULTS_EXCHANGE, aio_pika.ExchangeType.FANOUT, durable=True)

    # ── 3. Message handler ───────────────────────────────────────────────────
    async def on_message(message: aio_pika.IncomingMessage):
        async with message.process():
            payload = json.loads(message.body.decode())
            meta = payload.get("meta", {})
            job_id   = payload.get("job_id", "unknown")
            code     = payload.get("code", "")
            language = payload.get("language", "python")

            print(f"🔍 Scanning job {job_id} ({language})")

            # scan() runs Semgrep (bundled rules) + Bandit (Python only),
            # resolves the rules path, and returns a unified result dict.
            result = scan(code, language, job_id)
            all_findings = result["findings"]
            print(f"✅ job {job_id}: {len(all_findings)} finding(s)")

            await publish_findings(publish_channel, job_id, all_findings, meta)

    await queue.consume(on_message)
    print(f"👂 sast-scanner listening on [{CONSUME_QUEUE}]")

    await asyncio.Future()