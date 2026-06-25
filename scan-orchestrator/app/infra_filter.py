# scan-orchestrator/app/infra_filter.py   (OPTIONAL — not wired up by default)
#
# DECOUPLING NOTE: infra scanning is SCHEDULED (see "Design decision 2"), so the orchestrator
# does NOT trigger it. This module is the HOOK POINT for a future opt-in: "also kick an infra
# scan immediately when a push changes infra files" — on TOP of the nightly run. Until you want
# that, nothing here is called; it documents WHERE the decision lives.
from pathlib import PurePosixPath


def _is_infra_file(path: str) -> bool:
    """True if a changed file is infrastructure-as-code worth an out-of-band infra scan."""
    name   = PurePosixPath(path).name.lower()
    suffix = PurePosixPath(path).suffix.lower()
    return (
        suffix == ".tf"                                          # Terraform
        or suffix == ".dockerfile"                               # *.dockerfile
        or name == "dockerfile"                                  # bare Dockerfile
        or (name.startswith("docker-compose") and suffix in (".yml", ".yaml"))
        or suffix in (".yaml", ".yml")                           # k8s / Helm manifests (broad on purpose)
    )


def infra_files_changed(changed_files: list[str]) -> list[str]:
    """Return the subset of a push's changed files that are infra-relevant."""
    return [f for f in (changed_files or []) if _is_infra_file(f)]


async def maybe_dispatch_infra(payload: dict) -> None:
    """Hook called from the orchestrator's job handler IF push-triggered infra is enabled."""
    hits = infra_files_changed(payload.get("changed_files", []))
    if not hits:
        return  # no infra files in this push → nothing to consider

    # ⚠️ DELIBERATELY NOT DISPATCHING. Infra runs on a SCHEDULE (Design decision 2), so we do
    # NOT publish to scan_jobs.infra on push by default — that would re-introduce the very
    # per-push heaviness we decoupled away from.
    #
    # TODO(infra push-trigger): to ALSO scan infra immediately on infra-file changes, publish a
    # trigger to scan_jobs.infra here — the SAME publish the scheduler does:
    #
    #     await channel.declare_queue("scan_jobs.infra", durable=True)
    #     await channel.default_exchange.publish(
    #         aio_pika.Message(body=json.dumps({
    #             "job_id": payload["job_id"], "trigger": "push-infra", "code": "",
    #         }).encode(), delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
    #         routing_key="scan_jobs.infra",
    #     )
    #
    # Leaving it a logged no-op keeps the hook visible without changing behaviour.
    print(f"[infra-hook] {len(hits)} infra file(s) changed {hits} — "
          f"deferred to the scheduled run (push-trigger disabled).")