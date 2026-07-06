# Ways to Use CodeSheriff

CodeSheriff is a few things at once: a working security scanner, a reference architecture, a learning course, and a portfolio piece. This page lays out the different ways people actually use it, from "just run it and look" to "rip out a piece and drop it into my own stack."

Pick the section that matches why you're here.

---

## 1. Run it and watch a vulnerability get caught (the 5-minute demo)

The fastest way to understand the project is to see one finding travel the whole pipeline.

```bash
docker compose up -d --build
# wait for everything to be healthy
curl http://localhost/health
```

Then publish a job with a deliberately vulnerable snippet — RabbitMQ UI (http://localhost:15672, guest/guest) → **Exchanges** → `scan_jobs_fanout` → **Publish message**:

```json
{"job_id":"demo-1","language":"python","code":"import pickle\npickle.loads(open('x','rb').read())","meta":{}}
```

Now watch it land:
- **Dashboard** (http://localhost:8080) → the finding appears, the severity chart updates.
- **Grafana** (http://localhost:3000) → filter by the job's correlation ID and watch it move sast-scanner → ai-service → results-aggregator.
- The **AI Fixes** page shows Gemini's plain-English explanation and fix.

This is the "show, don't tell" path — great for a portfolio walkthrough or an interview screen-share.

---

## 2. As a local PR security gate

Point CodeSheriff at a real repository so it comments on your pull requests.

1. Set `github-service/.env` with a `GITHUB_TOKEN` (a fine-grained PAT with PR write access) and `GITHUB_REPO=owner/name`.
2. Expose `webhook-receiver` publicly — locally, `ngrok http 80` tunnels the Traefik gateway.
3. Add a GitHub webhook pointing at `https://<tunnel>/webhook`.
4. Open a PR → findings get posted back as a single Markdown comment with a severity table and AI fixes.

> Note the auth caveat: the `/webhook` route is behind JWT ForwardAuth, which is built for human/CI callers, not GitHub's HMAC signatures. For a production PR gate you'd swap in `X-Hub-Signature-256` verification. See [guides/triggering-scanners.md](guides/triggering-scanners.md).

---

## 3. As a CI/CD security template

The meta pipeline (`.github/workflows/security-pipeline.yml`) is reusable on its own. It shows how to:

- Run **secrets** (Gitleaks + TruffleHog), **SAST** (Semgrep + Bandit), **IaC** (Checkov), and **image CVE** (Trivy) scans as gated jobs.
- **Block a merge** on a CRITICAL CVE or a verified secret, while keeping DAST advisory.
- Scan **every service image in a matrix**, one leg each.
- Keep the workflow token **least-privilege** (`contents: read`), opting into `pull-requests: write` only where needed.

Copy the workflow, adjust the image names and `.checkov.yaml` skip-list, and you have a solid security gate for any Docker-Compose project.

---

## 4. Scan arbitrary code on demand (use it as a scanning API)

You don't need GitHub at all. Anything that can publish to RabbitMQ can drive the scanners:

```python
import aio_pika, json, asyncio

async def scan(code):
    conn = await aio_pika.connect_robust("amqp://guest:guest@localhost/")
    ch = await conn.channel()
    ex = await ch.declare_exchange("scan_jobs_fanout", aio_pika.ExchangeType.FANOUT, durable=True)
    await ex.publish(aio_pika.Message(json.dumps(
        {"job_id": "api-1", "language": "python", "code": code, "meta": {}}
    ).encode()), routing_key="")

asyncio.run(scan("eval(user_input)"))
```

Results land on `scan_results_fanout` (raw) and `ai_results_fanout` (enriched). Bind your own consumer to either and you've turned CodeSheriff into a scanning backend for your own frontend.

---

## 5. Reuse a single scanner in isolation

Each scanner is a self-contained container with a single tool wrapper (`app/scanner.py`) that takes code/targets and returns the standardised findings schema. If you only want, say, secret detection:

- Run just that service: `docker compose up -d secrets-scanner rabbitmq`.
- Publish to its private queue (`scan_jobs.secrets`) to bypass the fan-out.
- Read `scan_results_fanout` for its output.

The `scanner.py` files are also readable in isolation — each is a clean example of "wrap a security CLI as a subprocess, parse its JSON, normalise the output, handle timeouts and encoding correctly."

---

## 6. Reuse the dashboard as a findings viewer

`results-aggregator` is a standalone FastAPI + SQLite + Jinja2 dashboard. It consumes the enriched-findings schema and renders runs, filterable findings, AI fixes, and service health. If you have your own scanners that can emit the same envelope shape, you can point them at `ai_results_fanout` and get the dashboard for free — no changes needed.

It's also a compact reference for "server-rendered dashboard with a chart, no build step, no npm."

---

## 7. Reuse the AI enrichment layer

`ai-service` is a good template for "call an LLM safely in a pipeline":

- A strict output contract (always returns `severity_rating`, `explanation`, `remediation`, `cwe`).
- **Never raises to the caller** — any API/parse failure returns a safe stub, so one bad call can't stall the queue.
- **Rate-limit handling** with exponential backoff on HTTP 429.
- **Deduplication by rule** to conserve free-tier quota (170 findings → ~25 calls).

Swap the prompt and schema and it becomes a general "enrich each item in a stream with an LLM" service.

---

## 8. As a teaching / learning resource

The [guides/](guides/) folder is a full phase-by-phase course (13 phases) that builds the whole thing from an empty repo: FastAPI skeleton → RabbitMQ fan-out → each scanner → AI → PR comments → API gateway → DAST → CI/CD → observability → dashboard → polish. Every service is small and heavily commented on purpose.

Good for learning: async Python, message-driven microservices, container security, Traefik/JWT gateways, and how the security tools actually work.

---

## 9. As a portfolio / interview piece

CodeSheriff is designed to *demonstrate* competence across a lot of surface area in one project:

- Event-driven microservices with a real broker (not just REST-to-REST).
- Container and IaC security (Trivy, Checkov), SAST, secrets, DAST.
- AI-assisted triage with proper failure handling.
- An API gateway with auth and rate limiting.
- Structured logging + distributed tracing via correlation IDs.
- A gated CI/CD pipeline that dogfoods the project's own tools.

There's an interview questionnaire in `guides/` (local-only) that turns the architecture into practice Q&A.

---

## 10. Extend it — add your own scanner

The skeleton makes new scanners cheap. To add one:

1. Copy an existing scanner folder (e.g. `sast-scanner/`).
2. Replace `app/scanner.py` with your tool wrapper — take `(code, language, job_id)`, return the standardised result dict.
3. Set a unique `CONSUME_QUEUE` (e.g. `scan_jobs.mytool`) and `PORT` in `config.py`.
4. Add the service to `docker-compose.yml`.
5. It binds to `scan_jobs_fanout` automatically, so it starts receiving every job — and its findings flow to the AI layer and dashboard with zero changes elsewhere.

That "add a consumer without touching the producer" property is the whole point of the fan-out design.

---

## Which knobs matter

| I want to… | Change |
|------------|--------|
| Use a different AI model | `GEMINI_MODEL` in `ai-service/.env` |
| Run without any AI | Leave `GEMINI_API_KEY` unset — ai-service returns safe stubs |
| Change the infra scan cadence | `INFRA_CRON` in `scheduler/.env` |
| Change what DAST scans | `DAST_TARGETS` in `dast-scanner/.env` |
| Tune the IaC scan / skip checks | `.checkov.yaml` |
| Adjust rate limits | Traefik labels in `docker-compose.yml` |
| Change the JWT secret | `JWT_SECRET` in `gateway-auth/.env` |

---

*For architecture, the message flow, and the security model, start with the [main README](README.md). For how to fire and verify scans, see [guides/triggering-scanners.md](guides/triggering-scanners.md).*
