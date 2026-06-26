import json
import asyncio
import aio_pika

from app.config import RABBITMQ_URL, JOBS_EXCHANGE, CONSUME_QUEUE, RESULTS_EXCHANGE
from app.scanner import scan
from app.publisher import publish_findings


async def start_consumer():
    # ── 1. Connect with retry ────────────────────────────────────────────────
    # On `docker compose up`, RabbitMQ takes a few seconds to accept connections.
    # connect_robust also auto-reconnects if the broker restarts later.
    while True:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            break
        except Exception as e:
            print(f"RabbitMQ not ready, retrying in 2s... ({e})")
            await asyncio.sleep(2)

    # ── 2. Separate channels for consume vs publish ──────────────────────────
    # A channel is a lightweight virtual connection inside the one TCP connection.
    # Using one channel to consume and a second to publish avoids interleaving
    # issues and keeps the prefetch setting isolated to the consumer.
    consume_channel = await connection.channel()
    await consume_channel.set_qos(prefetch_count=1)   # one unacked message at a time
    publish_channel = await connection.channel()

    # Fan-out topology (see "Job Fan-out" above): every scanner binds its OWN queue to one
    # shared FANOUT exchange, so each job is COPIED to every scanner. If scanners shared a
    # single queue, RabbitMQ would round-robin and each job would reach only one of them.
    # declare_exchange/declare_queue are idempotent no-ops if they already exist (args must match).
   
    exchange = await consume_channel.declare_exchange(
        JOBS_EXCHANGE, aio_pika.ExchangeType.FANOUT, durable=True)
    queue = await consume_channel.declare_queue(CONSUME_QUEUE, durable=True)
    await queue.bind(exchange)  # this service's queue
    # subscribe my queue to the exchange
    # Results side is also fan-out: declare the exchange we publish to (not a plain
    # `scan_results` queue — that was the pre-fanout leftover that orphaned on every restart).
    await publish_channel.declare_exchange(
        RESULTS_EXCHANGE, aio_pika.ExchangeType.FANOUT, durable=True)

    # ── 3. Message handler ───────────────────────────────────────────────────
    async def on_message(message: aio_pika.IncomingMessage):
        # `async with message.process()` ACKs on clean exit and NACK/requeues if
        # an exception propagates — so a crash mid-scan returns the job to the queue.
        async with message.process():
            payload  = json.loads(message.body.decode())
            job_id   = payload.get("job_id", "unknown")
            code     = payload.get("code", "")
            language = payload.get("language", "python")

            print(f"🔍 Scanning job {job_id} ({language})")
            result = scan(code, language, job_id)        # ← the per-phase work
            all_findings = result["findings"]
            print(f"✅ job {job_id}: {len(all_findings)} finding(s)")

            await publish_findings(publish_channel, job_id, all_findings)

    # ── 4. Start consuming, then block forever ───────────────────────────────
    await queue.consume(on_message)        # registers the callback, returns immediately
    print(f"👂 secrets-scanner listening on [{CONSUME_QUEUE}]")
    await asyncio.Future()                 # park here forever so the task never ends