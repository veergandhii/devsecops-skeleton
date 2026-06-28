"""
scanner.py — CodeSheriff DAST Scanner
Waits for targets to be healthy, runs `zap-baseline.py` against each, parses the JSON
report into standardised findings (finding_type: "dast"). Ignores the job's `code`
(like infra-scanner) — the job is just a trigger.
"""

import subprocess
import os
import json
import time
import logging
import httpx

from app.config import DAST_TARGETS, SERVICE_NAME

logger = logging.getLogger(__name__)

WORKDIR = "/zap/wrk"                  # ZAP writes its report here
# ZAP riskcode → our standardised severity
_RISK = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}


def wait_for_target(url: str, timeout: int = 60) -> bool:
    """Poll <url>/health until it answers 200, or give up after `timeout` seconds."""
    deadline = time.time() + timeout
    health = url.rstrip("/") + "/health"
    while time.time() < deadline:
        try:
            if httpx.get(health, timeout=5).status_code == 200:
                return True
        except httpx.RequestError:
            pass
        time.sleep(3)
    logger.warning("target never became healthy: %s", health)
    return False


def run_zap_baseline(target: str) -> list[dict]:
    """Run a passive baseline scan against one target and return standardised findings."""
    # Unique report filename per target so concurrent-ish runs don't clobber each other.
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
    report_name = f"zap_{safe}.json"
    report_path = os.path.join(WORKDIR, report_name)

    cmd = [
        "zap-baseline.py",
        "-t", target,            # target URL
        "-J", report_name,       # JSON report (written into the cwd = WORKDIR)
        "-I",                    # do NOT fail (exit!=0) on warnings — we read the report
        "-m", "2",               # spider for max 2 minutes (bound the runtime)
    ]
    findings: list[dict] = []
    try:
        # cwd=WORKDIR so the report lands where we read it. zap-baseline.py exits 1 when it
        # finds issues even with -I in some versions; we don't gate on the exit code.
        subprocess.run(
            cmd, cwd=WORKDIR, capture_output=True, text=True,
            encoding="utf-8", errors="replace",   # House Rule #1
            timeout=300,
        )
        if not os.path.exists(report_path):
            logger.warning("no ZAP report for %s", target)
            return findings

        with open(report_path, encoding="utf-8") as f:
            report = json.load(f)

        # ZAP report shape: { "site": [ { "@name": url, "alerts": [ {...}, ... ] } ] }
        for site in report.get("site", []) or []:
            for alert in site.get("alerts", []) or []:
                instances = alert.get("instances", []) or []
                uri = instances[0].get("uri", target) if instances else target
                findings.append({
                    "tool":           "owasp-zap",
                    "rule_id":        alert.get("pluginid", "unknown"),
                    "finding_type":   "dast",
                    "severity":       _RISK.get(str(alert.get("riskcode", "0")), "INFO"),
                    "location":       uri,
                    "description":    alert.get("name", "DAST finding"),
                    "recommendation": _clean(alert.get("solution", "")),
                    # extras
                    "confidence":     alert.get("confidence", ""),
                    "reference":      _clean(alert.get("reference", "")),
                    "instances":      len(instances),
                })
    except subprocess.TimeoutExpired:
        logger.error("ZAP timed out on %s", target)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("failed reading ZAP report for %s: %s", target, e)

    logger.info("ZAP %s: %d findings", target, len(findings))
    return findings


def _clean(html: str) -> str:
    """ZAP solution/reference fields contain HTML <p> tags — strip the noisiest ones."""
    return (html or "").replace("<p>", " ").replace("</p>", " ").strip()


def scan(code: str, language: str, job_id: str) -> dict:
    all_findings: list[dict] = []
    for target in DAST_TARGETS:
        target = target.strip()
        if not target:
            continue
        if not wait_for_target(target):
            continue                       # skip unhealthy targets rather than scan a 503
        all_findings.extend(run_zap_baseline(target))

    result = {
        "job_id":         job_id,
        "language":       language,
        "service":        SERVICE_NAME,
        "total_findings": len(all_findings),
        "findings":       all_findings,
    }
    logger.info("dast scan complete", extra={"job_id": job_id, "total_findings": len(all_findings)})
    return result