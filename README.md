# 🛡️ CodeSheriff

**An event-driven DevSecOps pipeline that scans code the way a real security team would — then explains every finding in plain English and posts it back to your pull request.**

CodeSheriff is a portfolio-grade, microservices security platform. You point it at a code change; it fans that change out to a squad of specialist scanners (static analysis, secret detection, container/IaC checks, and live web scanning), enriches every finding with an AI explanation and a concrete fix, comments the results on the PR, and stores everything in a searchable dashboard. All of it runs locally with a single `docker compose up`.

It's built to be *read*. Every service is small, single-purpose, and heavily commented, and there's a full [guides/](guides/) course that walks through building it phase by phase.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [What it does, in one picture](#what-it-does-in-one-picture)
- [The services](#the-services)
- [How a scan actually flows](#how-a-scan-actually-flows)
- [The two pipelines](#the-two-pipelines)
- [Tech stack](#tech-stack)
- [Quick start](#quick-start)
- [Triggering a scan](#triggering-a-scan)
- [The dashboard](#the-dashboard)
- [Observability](#observability)
- [Security model](#security-model)
- [The findings schema](#the-findings-schema)
- [Project layout](#project-layout)
- [Design decisions worth knowing](#design-decisions-worth-knowing)
- [Further reading](#further-reading)

---

## Why this exists

Most "security scanning" in small projects is a single CI step that runs one tool, dumps a wall of red text, and gets ignored. Real security programs look different: **many specialised tools, each good at one thing, feeding a single place where a human can actually triage the results.**

CodeSheriff models that properly:

- **Separation of concerns** — each scanner is its own service, its own container, its own failure domain. One scanner crashing doesn't take the others down.
- **Loose coupling** — services never call each other directly. They talk through a message broker (RabbitMQ), so you can add, remove, or restart any scanner without touching the rest.
- **Findings you'll actually read** — an AI layer turns `B301: pickle.loads` into "this lets an attacker run arbitrary code; here's the three-line fix," and posts it right on the pull request.
- **Defence in depth** — an API gateway with JWT auth and rate limiting sits in front of everything; secrets live only in git-ignored `.env` files; scanners run read-only where they can.

It's simultaneously a working tool and a teaching artifact — a way to demonstrate that you understand microservices, async messaging, container security, and CI/CD, not just that you can run `npm audit`.

---

## What it does, in one picture

```
                          ┌───────────────────────┐
   git push / PR  ───────▶│    webhook-receiver    │  (the front door)
   or manual curl         └───────────┬───────────┘
                                       │ publishes ONE job
                                       ▼
                          ┌───────────────────────┐
                          │  RabbitMQ  scan_jobs_  │   fan-out: every scanner
                          │  fanout   (exchange)   │   gets its OWN copy
                          └───────────┬───────────┘
              ┌────────────┬──────────┼──────────┬─────────────┐
              ▼            ▼          ▼          ▼             ▼
        sast-scanner  secrets-   dast-scanner  (infra-scanner runs on a
        Semgrep+      scanner    OWASP ZAP      SCHEDULE, not on push)
        Bandit        Gitleaks+                      ▲
              │       TruffleHog     │               │ scheduler (cron)
              └────────────┴─────────┴───────────────┘
                                       │ each publishes findings
                                       ▼
                          ┌───────────────────────┐
                          │ RabbitMQ scan_results_ │   fan-out again
                          │ fanout   (exchange)    │
                          └───────────┬───────────┘
                          ┌───────────┴───────────┐
                          ▼                       ▼
                    scan-orchestrator         ai-service
                    (logs/traces)             enriches every finding
                                              with Gemini
                                                    │ publishes enriched
                                                    ▼
                                       ┌────────────────────────┐
                                       │ RabbitMQ ai_results_    │  fan-out
                                       │ fanout   (exchange)     │
                                       └───────────┬────────────┘
                                       ┌───────────┴────────────┐
                                       ▼                        ▼
                                github-service          results-aggregator
                                posts PR comment        stores in SQLite +
                                                        serves the dashboard
```

Everything upstream of the gateway is reachable only through **Traefik** (one public port), and every log line across every service carries the same **correlation ID** so you can trace one scan end to end.

---

## The services

Eleven services. Three have detailed, code-walkthrough READMEs as worked examples — [webhook-receiver](webhook-receiver/README.md), [sast-scanner](sast-scanner/README.md), and [secrets-scanner](secrets-scanner/README.md); the rest share the same skeleton and are documented inline and in the [guides/](guides/).

| Service | Port | Role | Key tools |
|---------|------|------|-----------|
| [webhook-receiver](webhook-receiver/README.md) | 8000 | The front door. Accepts GitHub webhooks (or manual calls) and mints one job per change. | FastAPI, aio_pika |
| scan-orchestrator | 8001 | Passive observer of results; the hook point for future push-triggered infra scans. | FastAPI, aio_pika |
| [sast-scanner](sast-scanner/README.md) | 8002 | Static analysis of source code for insecure patterns. | Semgrep, Bandit |
| [secrets-scanner](secrets-scanner/README.md) | 8003 | Finds committed credentials and API keys. | Gitleaks, TruffleHog |
| infra-scanner | 8004 | Scans built images for CVEs and IaC files for misconfigs. | Trivy, Checkov |
| ai-service | 8005 | Enriches each finding with a plain-English explanation + fix. | Google Gemini |
| github-service | 8006 | Renders findings into one Markdown PR comment and posts it. | PyGithub |
| dast-scanner | 8007 | Live (dynamic) scan of the running app's HTTP surface. | OWASP ZAP |
| scheduler | — | Fires the infra scan on a cron cadence (no HTTP surface). | APScheduler |
| gateway-auth | 8010 | Validates JWTs for Traefik's ForwardAuth on every protected request. | PyJWT |
| results-aggregator | 8080 | Consumes enriched findings, stores them in SQLite, serves the web dashboard. | FastAPI, Jinja2, Chart.js |

Plus the infrastructure containers: **RabbitMQ** (broker), **Traefik** (gateway), and **Loki + Promtail + Grafana** (log aggregation).

---

## How a scan actually flows

1. **A change arrives.** Someone pushes code, opens a PR, or fires a manual job. `webhook-receiver` turns it into a single job envelope and publishes it **once** to the `scan_jobs_fanout` exchange.
2. **Fan-out to scanners.** RabbitMQ copies that one job into each scanner's private queue. `sast-scanner`, `secrets-scanner`, and `dast-scanner` all wake up and scan in parallel. (`infra-scanner` deliberately sits this out — it runs on a schedule instead, because you don't want a full image CVE scan on every keystroke.)
3. **Findings come back.** Each scanner normalises its tool's output into one shared schema and publishes to the `scan_results_fanout` exchange.
4. **AI enrichment.** `ai-service` receives every result, and for each finding asks Gemini for a severity rating, plain-English explanation, concrete remediation, and CWE reference. It dedupes by rule so 170 identical CVEs cost ~25 API calls, not 170.
5. **Fan-out to consumers.** Enriched results go to `ai_results_fanout`, where two consumers pick them up independently: `github-service` posts a PR comment, and `results-aggregator` stores them and updates the dashboard.
6. **You look at the results** — on the PR, on the dashboard at `localhost:8080`, or in Grafana filtered by correlation ID.

The magic word throughout is **fan-out**: publish once, let the broker duplicate to every interested consumer. It's what lets you add a new consumer (like the dashboard) without touching the producer.

---

## The two pipelines

It's easy to conflate them, so here they are side by side:

| | **Product pipeline** | **Meta CI pipeline** |
|---|---|---|
| **What** | The live services scanning *whatever repo you point them at* | GitHub Actions scanning *this repo's own code* |
| **Where** | Your machine / a deploy, via `docker compose` | `.github/workflows/security-pipeline.yml` |
| **Trigger** | Webhook, manual publish, or schedule | push, PR to `main`, or the "Run workflow" button |
| **Runs** | The full RabbitMQ + scanner mesh | The same tool *images*, invoked directly (no broker) |
| **Gate** | Advisory — findings go to the dashboard/PR | Blocking — a CRITICAL CVE or a leaked secret fails the build |

The meta pipeline is CodeSheriff dogfooding itself: it builds the real scanner images and runs the exact same Semgrep/Bandit/Checkov/Trivy binaries against its own source on every push. See [guides/triggering-scanners.md](guides/triggering-scanners.md) for how to fire either one.

---

## Tech stack

- **Language:** Python 3.12 across every service.
- **Web framework:** FastAPI + Uvicorn (async, tiny, great for the health-check + background-consumer pattern).
- **Messaging:** RabbitMQ via `aio_pika` (async AMQP). Fan-out exchanges everywhere.
- **Gateway:** Traefik v3 with ForwardAuth (JWT) + rate-limiting middleware.
- **Storage:** SQLite (dashboard) — zero-config, file-on-a-volume durability.
- **AI:** Google Gemini via the `google-genai` SDK.
- **Observability:** structured JSON logs → Promtail → Loki → Grafana.
- **Security tooling:** Semgrep, Bandit, Gitleaks, TruffleHog, Trivy, Checkov, OWASP ZAP.
- **CI:** GitHub Actions (matrix image scanning, gated merges).
- **Everything containerised** with Docker Compose.

---

## Quick start

**Prerequisites:** Docker Desktop (or Docker Engine + Compose v2). That's it — every tool lives inside a container.

```bash
# 1. Clone
git clone https://github.com/veergandhii/devsecops-skeleton.git
cd devsecops-skeleton

# 2. Create the per-service .env files (they're git-ignored — see the note below)
#    Minimum viable: each service just needs RABBITMQ_URL. ai-service and github-service
#    want API keys to do their full job, but degrade gracefully without them.

# 3. Bring the whole stack up
docker compose up -d --build

# 4. Watch it come alive
docker compose ps
curl http://localhost/health          # through the gateway
```

Once it's up:

- **Dashboard:** http://localhost:8080
- **Traefik dashboard:** http://localhost:8081 (dev only)
- **RabbitMQ management UI:** http://localhost:15672 (guest / guest)
- **Grafana:** http://localhost:3000 (anonymous admin, dev only)

> **About `.env` files:** every service reads its secrets from a git-ignored `.env` (House Rule #7 — secrets never touch the repo). The `docker-compose.yml` points each service at its own `./service/.env`. For local dev, most just need `RABBITMQ_URL=amqp://guest:guest@rabbitmq/`. `ai-service` wants `GEMINI_API_KEY`; `github-service` wants `GITHUB_TOKEN` + `GITHUB_REPO`; `gateway-auth` wants a `JWT_SECRET`. Each service README lists exactly what it needs, and both degrade to a safe stub when a key is missing.

---

## Triggering a scan

There are several ways, covered in full in **[guides/triggering-scanners.md](guides/triggering-scanners.md)**. The two you'll use most:

**Manual job straight into RabbitMQ** (no auth, best for testing one scanner):
> RabbitMQ UI → http://localhost:15672 → Exchanges → `scan_jobs_fanout` → Publish message with a body like:
> ```json
> {"job_id":"demo-1","language":"python","code":"import pickle\npickle.loads(data)","meta":{}}
> ```

**Authenticated call through the gateway** (mimics a real caller):
```bash
TOKEN=$(python -c "import jwt,time; print(jwt.encode({'sub':'me','exp':int(time.time())+3600}, '<JWT_SECRET>', algorithm='HS256'))")
curl -X POST http://localhost/webhook -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"pull_request":{"id":1,"number":7},"repository":{"full_name":"you/repo"}}'
```

Then confirm each hop ran using queue depths, correlation-ID log filtering, and the dashboard (all explained in the triggering guide).

---

## The dashboard

`results-aggregator` serves a clean, four-page web UI at **http://localhost:8080**:

- **Overview** — KPI tiles (runs, total findings, criticals), a severity bar chart, and recent-run history.
- **Findings** — every finding, filterable by severity and tool, with a status-coloured severity pill.
- **AI Fixes** — findings grouped by file, each showing the AI's suggested remediation.
- **Services** — live health of all services (green/red dots).

It's server-rendered (FastAPI + Jinja2, Chart.js from a CDN) — no build step, no npm — and stores everything in a SQLite file on a named volume so data survives restarts. See the `results-aggregator/` service and [guides/phase-12-dashboard.md](guides/phase-12-dashboard.md) for details.

---

## Observability

Every service logs **structured JSON** (not free text) through a shared `logging_config.py`. Each log line carries:

- `service` — which service emitted it
- `correlation_id` — minted once at the origin (webhook or scheduler) and carried on every RabbitMQ message header through every hop
- `level`, `timestamp`, `message`, plus any structured extras

Promtail scrapes container logs → Loki indexes them → Grafana (pre-provisioned with the Loki datasource) lets you query. To trace one scan across all services:

```
{service=~".+"} |= "<correlation_id>"
```

That single ID stitches together the webhook, all three scanners, the AI enrichment, the PR comment, and the dashboard write — the thing that makes a distributed system debuggable.

---

## Security model

- **One front door.** After the gateway phase, only Traefik's port 80 is exposed to the host. Internal services aren't directly reachable — they talk to each other by service name on the Docker network.
- **JWT on protected routes.** Traefik's ForwardAuth middleware calls `gateway-auth/verify` for every protected request; no valid `Bearer` token → 401 before the request ever reaches a service.
- **Open health checks.** `/health` is deliberately unauthenticated (a higher-priority Traefik router) so monitoring and DAST can probe liveness without a token.
- **Rate limiting.** Traefik caps requests (10/s sustained, burst 20) to blunt abuse.
- **Secrets stay out of git.** All `.env` files are git-ignored; the meta CI pipeline materialises throwaway env files from GitHub Actions secrets.
- **Least privilege in CI.** The workflow's `GITHUB_TOKEN` is read-only by default; only the PR-comment job opts into `pull-requests: write`.
- **Read-only mounts.** `infra-scanner` mounts the project root read-only; Traefik mounts the Docker socket read-only.

> **A deliberate dev/prod boundary:** `infra-scanner` mounts the host Docker socket so Trivy can inspect locally-built images. That grants root-equivalent host access and is a **dev-only** convenience. In CI (Phase 10), Trivy runs as its own step against images directly — **no socket, no in-container daemon access.** Never ship the socket-mount version to production.

---

## The findings schema

Every scanner, regardless of the tool underneath, normalises its output into one envelope. This is the contract the AI service and dashboard depend on:

```jsonc
{
  "job_id":    "abc-123",            // echoes the job that triggered the scan
  "service":   "secrets-scanner",    // which scanner produced this
  "timestamp": "2026-06-23T10:30:00+00:00",
  "count":     2,
  "findings": [
    {
      "tool":         "gitleaks",          // the underlying CLI tool
      "rule_id":      "generic-api-key",   // tool's rule/check/CVE id
      "finding_type": "secret",            // secret | sast | cve | misconfiguration | dast
      "severity":     "CRITICAL",          // CRITICAL | HIGH | MEDIUM | LOW | INFO
      "location":     "target.py:12",      // file:line (or image:tag for CVEs)
      "description":  "Generic API key detected",
      "recommendation": "Rotate immediately; move to an environment variable."
      // + optional tool-specific extras (masked secret_preview, code_snippet, package, …)
    }
  ]
}
```

`finding_type` is the unifying field the dashboard filters on. `severity` is always one of the five uppercase values — each scanner maps its tool's native scale onto that set.

---

## Project layout

```
devsecops-skeleton/
├── docker-compose.yml         # the whole stack: services + rabbitmq + traefik + observability
├── .github/workflows/         # the meta CI pipeline (security-pipeline.yml)
├── .checkov.yaml              # IaC scan scope + justified skips
├── .gitattributes             # LF normalisation across the team
│
├── webhook-receiver/          # ─┐
├── scan-orchestrator/         #  │
├── sast-scanner/              #  │
├── secrets-scanner/           #  │  each service:
├── infra-scanner/             #  │    app/           (FastAPI app + consumer + logic)
├── ai-service/                #  ├─▶  Dockerfile
├── github-service/            #  │    requirements.txt
├── dast-scanner/              #  │    .env           (git-ignored)
├── scheduler/                 #  │    README.md      (3 services have deep-dives)
├── gateway-auth/              #  │
├── results-aggregator/        # ─┘
│
├── observability/             # loki / promtail / grafana configs
├── guides/                    # the full build course (git-ignored, personal)
└── USAGES.md                  # ways to use / adapt this project
```

Every service follows the same skeleton: `app/main.py` (FastAPI + a background consumer via lifespan), `app/config.py` (env-driven config), `app/consumer.py` (RabbitMQ loop), `app/logging_config.py` (shared JSON logger), `app/routes/health.py`. Scanners add `app/scanner.py` (the tool wrapper) and `app/publisher.py` (the standardised envelope).

---

## Design decisions worth knowing

- **Why fan-out exchanges instead of one shared queue?** A shared queue round-robins — each job would reach only *one* scanner. Fan-out copies each job to every scanner's private queue, so all of them see it. The same pattern is applied three times: jobs, results, and AI results.
- **Why is infra-scanner on a schedule, not on push?** Image CVE + IaC scans are heavy and their inputs (base images, published CVEs) change on a daily cadence, not per-commit. The `scheduler` service fires it nightly. The hook to *also* trigger it on infra-file changes exists (`scan-orchestrator/app/infra_filter.py`) but is a deliberate no-op by default.
- **Why SQLite for the dashboard?** Single instance, file-on-a-volume durability, zero extra containers. Postgres would be overkill for one dashboard.
- **Why does the AI service dedupe?** The free Gemini tier is rate-limited. Identical findings (same `rule_id`) get identical enrichment, so it calls the API once per unique rule and reuses the result — turning 170 findings into ~25 calls.
- **Why does nothing crash the queue?** Every external call (Gemini, GitHub) is wrapped so a failure returns a safe stub / logs and moves on. One bad API call can't stall the pipeline.

---

## Further reading

- **[USAGES.md](USAGES.md)** — the many ways to use, adapt, and extend this project.
- **[guides/](guides/)** — the full phase-by-phase build course (local-only).
- **[guides/triggering-scanners.md](guides/triggering-scanners.md)** — every way to fire a scan and verify it ran.
- **Worked-example service READMEs** — [webhook-receiver](webhook-receiver/README.md), [sast-scanner](sast-scanner/README.md), [secrets-scanner](secrets-scanner/README.md) walk through their code in detail; every other service follows the same skeleton.

---

*CodeSheriff is a learning-and-portfolio project. It demonstrates event-driven microservices, container security, AI-assisted triage, and gated CI/CD — the shape of a real security platform, sized to fit in your head.*
