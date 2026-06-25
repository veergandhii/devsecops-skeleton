"""
scanner.py - CodeSheriff Infra Scanner
Trivy scans built Docker images for CVEs; Checkov scans IaC files for misconfigurations.
Unlike the other scanners, this one ignores the job's `code` and scans the mounted
project at WORKSPACE_PATH. Output uses the standardised schema (finding_type: cve | misconfiguration).
"""

import subprocess
import os
import json
import logging
import yaml                       # parse docker-compose.yml into an image list
from pathlib import Path          # recursive Dockerfile discovery

from app.config import WORKSPACE_PATH, SERVICE_NAME, COMPOSE_PROJECT_NAME

logger = logging.getLogger(__name__)


# Discover which images to scan, by reading docker-compose.yml
def extract_images_from_compose(compose_path: str) -> list[str]:
    """
    Return the image names Compose builds for our services.

    For a service with `build:` and no explicit `image:`, Compose v2 names the image
    "<project>-<service>" (project defaults to the directory name). For a service with an
    explicit `image:`, we use that. Third-party images (rabbitmq) are skipped because patching
    those is upstream's job, and they would add huge noise.
    """
    try:
        with open(compose_path, encoding="utf-8") as f:
            compose = yaml.safe_load(f)
    except Exception as e:
        logger.error("failed to read docker-compose.yml: %s", e)
        return []

    images: list[str] = []
    for name, cfg in (compose.get("services", {}) or {}).items():
        cfg = cfg or {}
        if "build" not in cfg:
            continue                      # only scan images WE build
        if cfg.get("image"):
            images.append(cfg["image"])   # explicit name wins
        else:
            images.append(f"{COMPOSE_PROJECT_NAME}-{name}")   # v2 default naming

    logger.info("images to scan: %s", images)
    return images


# TRIVY: image CVE scan
def run_trivy_image(image: str) -> list[dict]:
    cmd = [
        "trivy", "image",
        "--scanners", "vuln",            # CVEs only (Gitleaks/Checkov cover the rest)
        "--severity", "HIGH,CRITICAL",   # actionable noise floor
        "--format", "json",
        "--quiet",                        # no progress spinner in logs
        "--timeout", "10m",              # first run downloads the DB; be patient
        image,
    ]
    findings: list[dict] = []
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",   # House Rule #1
            timeout=600,
        )
        if not result.stdout.strip():
            logger.warning("trivy: no output for %s (stderr: %s)", image, result.stderr[:200])
            return findings

        data = json.loads(result.stdout)
        for res in data.get("Results", []) or []:
            target = res.get("Target", image)
            for v in res.get("Vulnerabilities", []) or []:
                pkg     = v.get("PkgName", "unknown")
                version = v.get("InstalledVersion", "unknown")
                fixed   = v.get("FixedVersion", "")
                cve     = v.get("VulnerabilityID", "UNKNOWN")
                rec = (
                    f"Upgrade {pkg} from {version} to {fixed}."
                    if fixed else
                    f"No fix published yet for {pkg} {version}. Consider a slimmer/newer base "
                    "image, or remove the package if unused."
                )
                findings.append({
                    "tool":           "trivy",
                    "rule_id":        cve,
                    "finding_type":   "cve",
                    "severity":       v.get("Severity", "UNKNOWN").upper(),  # already CRITICAL/HIGH/...
                    "location":       f"image:{image} ({pkg}@{version})",
                    "description":    v.get("Title") or f"{cve} in {pkg}",
                    "recommendation": rec,
                    # tool-specific extras
                    "package":        pkg,
                    "installed_version": version,
                    "fixed_version":  fixed or "none",
                })
    except subprocess.TimeoutExpired:
        logger.error("trivy timed out scanning %s", image)
    except FileNotFoundError:
        logger.error("trivy binary not found - installed in the Dockerfile?")
    except json.JSONDecodeError as e:
        logger.error("failed to parse trivy output for %s: %s", image, e)

    logger.info("trivy %s: %d findings", image, len(findings))
    return findings


# CHECKOV: IaC misconfiguration scan
# OSS Checkov reports no severity. Map a few high-impact checks up; default the rest.
_CHECKOV_HIGH = {
    "CKV_DOCKER_1",  # expose port 22 / sshd
    "CKV_DOCKER_2",  # no HEALTHCHECK -> here we treat privileged/root as high; adjust to taste
    "CKV_DOCKER_3",  # last USER is root
}

def _checkov_severity(check_id: str) -> str:
    return "HIGH" if check_id in _CHECKOV_HIGH else "MEDIUM"


def run_checkov_file(file_path: str) -> list[dict]:
    cmd = ["checkov", "-f", file_path, "-o", "json", "--compact", "--quiet"]
    findings: list[dict] = []
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",   # House Rule #1
            timeout=180,
        )
        if not result.stdout.strip():
            return findings

        data = json.loads(result.stdout)
        # Checkov returns a dict for one framework, or a LIST of dicts when a file matches
        # multiple frameworks. Normalise to a list.
        for block in (data if isinstance(data, list) else [data]):
            for chk in block.get("results", {}).get("failed_checks", []) or []:
                check_id = chk.get("check_id", "UNKNOWN")
                rng = chk.get("file_line_range", [0, 0]) or [0, 0]
                rel = os.path.relpath(file_path, WORKSPACE_PATH)   # readable path in output
                findings.append({
                    "tool":           "checkov",
                    "rule_id":        check_id,
                    "finding_type":   "misconfiguration",
                    "severity":       _checkov_severity(check_id),
                    "location":       f"{rel}:L{rng[0]}-{rng[1]}",
                    "description":    chk.get("check_name", "Misconfiguration"),
                    "recommendation": (
                        f"{chk.get('check_name','')}. Guidance: "
                        f"{chk.get('guideline') or 'https://www.checkov.io/5.Policy%20Index/all.html'}"
                    ),
                })
    except subprocess.TimeoutExpired:
        logger.error("checkov timed out on %s", file_path)
    except FileNotFoundError:
        logger.error("checkov binary not found - installed in the Dockerfile?")
    except json.JSONDecodeError as e:
        logger.error("failed to parse checkov output for %s: %s", file_path, e)

    logger.info("checkov %s: %d findings", file_path, len(findings))
    return findings


def find_dockerfiles(workspace: str) -> list[str]:
    """Recursively find every file literally named 'Dockerfile' under the workspace."""
    return [str(p) for p in Path(workspace).rglob("Dockerfile")]


# MAIN ENTRY POINT: called by consumer.py (code/language unused on purpose)
def scan(code: str, language: str, job_id: str) -> dict:
    all_findings: list[dict] = []
    compose_path = os.path.join(WORKSPACE_PATH, "docker-compose.yml")

    # 1) Trivy: scan every image we build
    if os.path.exists(compose_path):
        for image in extract_images_from_compose(compose_path):
            all_findings.extend(run_trivy_image(image))
        # 2) Checkov: scan the compose file itself
        all_findings.extend(run_checkov_file(compose_path))
    else:
        logger.warning("docker-compose.yml not found at %s", compose_path)

    # 3) Checkov: scan every Dockerfile in the project
    for dockerfile in find_dockerfiles(WORKSPACE_PATH):
        all_findings.extend(run_checkov_file(dockerfile))

    result = {
        "job_id":         job_id,
        "language":       language,
        "service":        SERVICE_NAME,
        "total_findings": len(all_findings),
        "findings":       all_findings,
    }
    logger.info("infra scan complete", extra={"job_id": job_id, "total_findings": len(all_findings)})
    return result
