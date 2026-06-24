"""
scanner.py — CodeSheriff Secrets Scanner
Runs Gitleaks + TruffleHog against code received from RabbitMQ, returns a unified
findings list in the standardised schema.

Design (mirrors sast-scanner):
- Both tools are CLI binaries installed in the Dockerfile, run via subprocess.
- Code arrives as a string → we write it to a temp DIRECTORY (these tools scan
  directories/files, not stdin) → run both tools against that dir → parse → mask → return.
- Secrets are masked before they ever enter a log line or the result payload (House Rule #6).
- Subprocess uses encoding="utf-8", errors="replace" (House Rule #1).
- Line endings normalised to LF before writing (House Rule #2).
"""

import subprocess          # run gitleaks / trufflehog as child processes
import tempfile            # create a temp dir that's auto-deleted after the scan
import os                  # path joining, file existence checks
import json                # parse tool output (JSON array / JSONL)
import logging             # structured logging — never bare print() in library code
from datetime import datetime, timezone  # (not strictly needed here; publisher stamps time)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: mask a secret for safe logging/output (House Rule #6)
# ─────────────────────────────────────────────────────────────────────────────
def mask_secret(secret: str) -> str:
    """
    Show first 6 + last 3 chars so a human can identify WHICH credential leaked,
    without ever recording the whole value.
      "AKIAIOSFODNN7EXAMPLE" -> "AKIAIO...PLE"
    Anything <= 9 chars can't be safely previewed, so we hide it entirely.
    """
    if not secret:
        return ""
    if len(secret) <= 9:
        return "***"
    return f"{secret[:6]}...{secret[-3:]}"


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: normalise line endings (House Rule #2)
# ─────────────────────────────────────────────────────────────────────────────
def normalise_code(code: str) -> str:
    """Strip surrounding whitespace and convert CRLF/CR to LF before writing to disk."""
    return code.strip().replace('\r\n', '\n').replace('\r', '\n')


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: language -> file extension (so the temp file looks like real source)
# ─────────────────────────────────────────────────────────────────────────────
def _lang_to_ext(language: str) -> str:
    return {
        "python": ".py", "javascript": ".js", "typescript": ".ts",
        "go": ".go", "java": ".java", "yaml": ".yaml", "json": ".json",
    }.get(language.lower(), ".txt")


# ─────────────────────────────────────────────────────────────────────────────
# GITLEAKS
# ─────────────────────────────────────────────────────────────────────────────
def run_gitleaks(scan_dir: str) -> list[dict]:
    """
    Run Gitleaks in --no-git mode over a directory and return standardised findings.

    Flags explained:
      detect              : the scan subcommand
      --no-git            : treat the path as plain files (no git history) — our code
                            arrived as a string, there is no repo here
      --source <dir>      : directory to scan
      --report-format json: machine-readable output...
      --report-path <f>   : ...written to THIS FILE (Gitleaks does not print findings to stdout)
      --exit-code 0       : force exit 0 even when secrets are found, so subprocess doesn't
                            treat "found a secret" as a failure (default exit code is 1)
    """
    report_path = os.path.join(scan_dir, "gitleaks-report.json")
    cmd = [
        "gitleaks", "detect",
        "--no-git",
        "--source", scan_dir,
        "--report-format", "json",
        "--report-path", report_path,
        "--exit-code", "0",
    ]

    findings: list[dict] = []
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",   # House Rule #1
            timeout=60,
        )
        # Gitleaks logs progress to stderr; only useful when debugging.
        if result.stderr:
            logger.debug("gitleaks stderr: %s", result.stderr[:300])

        # Findings live in the report FILE, not stdout. No file => nothing to do.
        if not os.path.exists(report_path):
            logger.info("gitleaks complete: 0 findings (no report file)")
            return findings

        with open(report_path, encoding="utf-8") as f:
            content = f.read().strip()

        # An empty file or literal "null" both mean "no secrets found".
        if not content or content == "null":
            logger.info("gitleaks complete: 0 findings")
            return findings

        report = json.loads(content)   # Gitleaks writes a JSON ARRAY of finding objects

        # Each item looks like:
        #   {"RuleID":"aws-access-token","Description":"AWS Access Key",
        #    "Match":"AKIA...","Secret":"AKIA...","File":"target.py","StartLine":4, ...}
        for item in report if isinstance(report, list) else []:
            secret_value = item.get("Secret", "")
            # Gitleaks 8.x uses "StartLine"; older builds used "Line". Cover both.
            line = item.get("StartLine", item.get("Line", 0))
            file = os.path.basename(item.get("File", "unknown"))  # strip temp-dir prefix

            findings.append({
                "tool":           "gitleaks",
                "rule_id":        item.get("RuleID", "unknown"),
                "finding_type":   "secret",
                "severity":       "CRITICAL",          # a real credential is always critical
                "location":       f"{file}:{line}",
                "description":    item.get("Description", "Secret detected"),
                "recommendation": (
                    "Rotate this credential now — treat it as compromised. Move it to an "
                    "environment variable or a secrets manager. If it was ever committed, "
                    "purge it from git history (git filter-repo / BFG)."
                ),
                # ── tool-specific extra (masked!) ──
                "secret_preview": mask_secret(secret_value),
            })

    except subprocess.TimeoutExpired:
        logger.error("gitleaks timed out after 60s")
    except FileNotFoundError:
        logger.error("gitleaks binary not found — is it installed in the Dockerfile?")
    except json.JSONDecodeError as e:
        logger.error("failed to parse gitleaks report: %s", e)

    logger.info("gitleaks complete: %d findings", len(findings))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# TRUFFLEHOG
# ─────────────────────────────────────────────────────────────────────────────
def run_trufflehog(scan_dir: str) -> list[dict]:
    """
    Run TruffleHog v3 in filesystem mode and return standardised findings.

    Flags explained:
      filesystem <dir>  : scan a directory of files (vs git/github/s3 modes)
      --json            : emit ONE JSON OBJECT PER LINE (JSONL) — NOT a JSON array
      --no-verification : do not call external APIs to check if creds are live
                          (offline, fast, and we must never USE a found credential)
    """
    cmd = ["trufflehog", "filesystem", scan_dir, "--json", "--no-verification"]

    findings: list[dict] = []
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",   # House Rule #1
            timeout=120,                           # entropy scanning can be slower → 2 min
        )

        # JSONL: split on newlines, parse each non-empty line on its own.
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue   # TruffleHog also prints non-JSON status lines; skip them

            # A real detection always has a DetectorName. Lines without it are logs.
            detector = item.get("DetectorName")
            if not detector:
                continue

            # Location is nested: SourceMetadata.Data.Filesystem.{file,line}
            fs = (item.get("SourceMetadata", {})
                      .get("Data", {})
                      .get("Filesystem", {}))
            file = os.path.basename(fs.get("file", "unknown"))
            line_num = fs.get("line", 0)

            raw_secret = item.get("Raw", "")

            findings.append({
                "tool":           "trufflehog",
                "rule_id":        detector,            # e.g. "AWS", "GitHub", "Stripe"
                "finding_type":   "secret",
                "severity":       "CRITICAL",
                "location":       f"{file}:{line_num}",
                "description":    f"Potential {detector} credential detected",
                "recommendation": (
                    f"Rotate this {detector} credential immediately. Move it to an environment "
                    "variable or secrets manager (Vault / AWS Secrets Manager)."
                ),
                # ── tool-specific extras ──
                "secret_preview": mask_secret(raw_secret),
                "verified":       item.get("Verified", False),
            })

    except subprocess.TimeoutExpired:
        logger.error("trufflehog timed out after 120s")
    except FileNotFoundError:
        logger.error("trufflehog binary not found — is it installed in the Dockerfile?")

    logger.info("trufflehog complete: %d findings", len(findings))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT — called by consumer.py
# ─────────────────────────────────────────────────────────────────────────────
def scan(code: str, language: str, job_id: str) -> dict:
    """
    Write the code to a temp directory, run both tools against it, and return the
    unified result dict. consumer.py reads result["findings"] and hands it to the
    publisher. Same call signature as sast-scanner's scan() so the consumer template
    is unchanged.
    """
    normalised = normalise_code(code)
    ext = _lang_to_ext(language)
    all_findings: list[dict] = []

    # TemporaryDirectory auto-deletes everything (the source file AND gitleaks' report)
    # when the `with` block exits — no cleanup code, no leftover secrets on disk.
    with tempfile.TemporaryDirectory() as scan_dir:
        target = os.path.join(scan_dir, f"target{ext}")
        with open(target, "w", encoding="utf-8") as f:
            f.write(normalised)

        logger.info("starting secrets scan", extra={"job_id": job_id})
        all_findings.extend(run_gitleaks(scan_dir))
        all_findings.extend(run_trufflehog(scan_dir))

    result = {
        "job_id":         job_id,
        "language":       language,
        "service":        "secrets-scanner",
        "total_findings": len(all_findings),
        "findings":       all_findings,
    }
    logger.info(
        "secrets scan complete",
        extra={"job_id": job_id, "total_findings": len(all_findings)},
    )
    return result