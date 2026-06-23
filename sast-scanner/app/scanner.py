"""
scanner.py — CodeSheriff SAST Scanner
Runs Semgrep (local OSS rules) + Bandit against code received from RabbitMQ.
Produces a unified findings list with remediation advice per finding.

Key design decisions documented here:
- Semgrep: OSS mode ONLY with bundled local rules (Pro rules are cloud-only/paid)
- Bandit: handles all real Python security detection offline
- Code normalisation: CRLF → LF before passing to tools (prevents 0-byte scan bug)
- Subprocess: each tool runs against a NamedTemporaryFile, stdout captured, stderr logged
- --disable-version-check: avoids a semgrep network call on every run
"""

import subprocess  # runs external CLI tools (semgrep, bandit) as child processes
import tempfile    # creates temp files that are cleaned up after the scan
import os          # path joining, file operations
import json        # parsing tool JSON output
import logging     # structured logging — no bare print() calls
from pathlib import Path  # cleaner path handling than os.path strings

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# REMEDIATION MAP
# Maps Semgrep rule IDs and Bandit test IDs to human-readable remediation text.
# This is what gets added to each finding's "remediation" field in the output JSON.
# Keeps remediation logic here, not scattered through consumer.py or publisher.py.
# ─────────────────────────────────────────────────────────────────────────────
REMEDIATION_MAP = {
    # ── Semgrep rule remediations ──────────────────────────────────────────
    "hardcoded-password": (
        "Move the credential to an environment variable. "
        "Read it with os.environ['SECRET_NAME']. "
        "Add the variable to .env (local) and your CI secrets (production). "
        "If already committed, rotate the credential immediately — git history is permanent."
    ),
    "pickle-deserialization": (
        "Replace pickle with a safe serialisation format. "
        "For configs: JSON or TOML. For typed objects: dataclasses + json, pydantic, or protobuf. "
        "If you must use pickle for internal data, never unpickle bytes that crossed a network boundary."
    ),
    "subprocess-shell-true": (
        "Remove shell=True and pass the command as a list: "
        "subprocess.run(['ls', '-la', path]) not subprocess.run(f'ls -la {path}', shell=True). "
        "List form bypasses the shell entirely so injection is not possible."
    ),
    "dangerous-eval": (
        "Replace eval()/exec() with safer alternatives. "
        "To parse literals (numbers, strings, dicts): use ast.literal_eval(). "
        "To dispatch to functions: use a dict mapping names to callables. "
        "There is almost no legitimate reason for eval() in production code."
    ),
    "sql-injection-string-format": (
        "Use parameterised queries. Pass values as a tuple, never formatted into the SQL string. "
        "Example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)) "
        "The driver escapes the value; string formatting does not."
    ),
    "hardcoded-ip-address": (
        "Move the IP/hostname to an environment variable or config file. "
        "Example: HOST = os.environ.get('DB_HOST', 'localhost') "
        "Use service names in Docker Compose networks instead of IPs."
    ),
    "weak-hash-algorithm": (
        "For data integrity: use hashlib.sha256() or hashlib.sha3_256(). "
        "For passwords: use bcrypt, argon2-cffi, or passlib — never a raw hash. "
        "Raw hashes (even SHA-256) are not safe for passwords due to speed; use a KDF."
    ),
    "insecure-random": (
        "Replace with the secrets module for any security-sensitive value. "
        "secrets.token_hex(32) → 64-char hex token. "
        "secrets.token_urlsafe(32) → URL-safe base64 token. "
        "secrets.choice(alphabet) → cryptographically random character. "
        "Keep random module only for simulations and non-security shuffles."
    ),
    "assert-used-for-auth": (
        "Replace assert with explicit if/raise. "
        "Example: if not user.is_admin(): raise PermissionError('Admin required') "
        "Python strips assert when run with -O flag; your security check silently disappears."
    ),
    "bind-all-interfaces": (
        "Control the bind address via environment variable, not hardcoded logic. "
        "Example: host = os.environ.get('BIND_HOST', '127.0.0.1') "
        "In Docker Compose, port mapping handles exposure; the service itself should bind 0.0.0.0 "
        "only when you explicitly intend to and understand the network topology."
    ),
    "xxe-via-xml-parse": (
        "Install defusedxml: pip install defusedxml. "
        "Replace xml.etree.ElementTree with defusedxml.ElementTree — same API, safe defaults. "
        "For lxml: parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True) "
        "then pass parser= to fromstring() or parse()."
    ),
    "flask-debug-mode": (
        "Remove debug=True from app.run(). "
        "Control debug mode via environment: export FLASK_ENV=development (local only). "
        "In production FLASK_ENV must be 'production' or omitted entirely."
    ),
    "yaml-load-unsafe": (
        "Replace yaml.load(data) with yaml.safe_load(data). "
        "safe_load() only deserialises standard YAML types and cannot construct Python objects. "
        "If you need to load Python-specific YAML tags internally, use yaml.load(data, Loader=yaml.FullLoader) "
        "but NEVER on untrusted input."
    ),
    # ── Bandit test ID remediations ────────────────────────────────────────
    "B105": (  # hardcoded_password_string
        "Hardcoded password string detected by Bandit. "
        "Move to environment variable: os.environ['PASSWORD']. "
        "Rotate the credential if it has been committed to Git."
    ),
    "B106": (  # hardcoded_password_funcarg
        "Password passed as a hardcoded function argument. "
        "Pass it via environment variable instead: connect(password=os.environ['DB_PASS'])."
    ),
    "B107": (  # hardcoded_password_default
        "Hardcoded default password in function signature. "
        "Remove the default: def connect(password): not def connect(password='admin')."
    ),
    "B301": (  # pickle
        "pickle.loads() detected. Unpickling untrusted data is arbitrary code execution. "
        "Use JSON for data interchange. If internal use only, sign the pickle bytes with HMAC first."
    ),
    "B302": (  # marshal
        "marshal.loads() is unsafe on untrusted data — similar risks to pickle. "
        "Use JSON or a validated schema instead."
    ),
    "B303": (  # MD5
        "MD5 used for hashing. MD5 is cryptographically broken. "
        "Use hashlib.sha256() for integrity. Use bcrypt/argon2 for passwords."
    ),
    "B304": (  # ciphers
        "Weak or deprecated cipher detected. Use AES-256-GCM or ChaCha20-Poly1305 via the cryptography library."
    ),
    "B305": (  # cipher with ECB mode
        "ECB cipher mode is insecure — identical plaintext blocks produce identical ciphertext blocks. "
        "Use GCM or CBC with a random IV."
    ),
    "B306": (  # mktemp
        "tempfile.mktemp() has a race condition (TOCTOU). "
        "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead."
    ),
    "B307": (  # eval
        "eval() detected. See dangerous-eval remediation. "
        "Use ast.literal_eval() or a dispatch dict."
    ),
    "B311": (  # random
        "random module used in security context. "
        "Use the secrets module for tokens, IDs, and OTPs."
    ),
    "B314": (  # xml.etree.ElementTree parse
        "xml.etree.ElementTree.parse() is XXE-vulnerable. Install and use defusedxml."
    ),
    "B318": (  # minidom parse
        "xml.dom.minidom.parse() is XXE-vulnerable. Install and use defusedxml."
    ),
    "B320": (  # lxml parse
        "lxml.etree.parse() with default settings processes external entities (XXE). "
        "Use lxml.etree.XMLParser(resolve_entities=False, no_network=True)."
    ),
    "B324": (  # hashlib new with weak alg
        "Weak hash via hashlib.new(). Use sha256 or sha3_256."
    ),
    "B401": (  # import telnetlib
        "telnetlib imported. Telnet transmits data including credentials in plaintext. Use SSH/paramiko."
    ),
    "B403": (  # import pickle
        "pickle module imported. Ensure pickle.loads() is never called on untrusted data. "
        "Consider replacing with json or a schema-validated format."
    ),
    "B404": (  # import subprocess
        "subprocess module imported. Ensure shell=True is never used with user-controlled input."
    ),
    "B501": (  # request with verify=False
        "SSL verification disabled (verify=False). This allows MITM attacks. "
        "Never disable SSL verification in production. Fix the certificate instead."
    ),
    "B502": (  # ssl with bad version
        "Deprecated SSL/TLS version specified. Use ssl.PROTOCOL_TLS_CLIENT and let Python negotiate."
    ),
    "B506": (  # yaml load
        "yaml.load() without SafeLoader is code execution on untrusted input. Use yaml.safe_load()."
    ),
    "B601": (  # paramiko exec
        "paramiko exec_command() with user input can lead to command injection over SSH."
    ),
    "B602": (  # subprocess with shell
        "subprocess shell=True detected by Bandit. See subprocess-shell-true remediation."
    ),
    "B603": (  # subprocess without shell
        "subprocess called without shell=True — generally safer. "
        "Ensure the command list does not contain user-controlled data that could alter argument meaning."
    ),
    "B604": (  # any function with shell
        "Function call that may invoke a shell. Verify no user input reaches shell metacharacters."
    ),
    "B605": (  # start process with shell
        "os.system() or similar shell-invoking call. Replace with subprocess.run() without shell=True."
    ),
    "B606": (  # start process with no shell
        "os.execl/os.execv — ensure arguments are not user-controlled."
    ),
    "B607": (  # start process partial path
        "Subprocess called with a partial path (no absolute path). "
        "Use absolute paths to prevent PATH hijacking: /usr/bin/ls not ls."
    ),
    "B608": (  # sql injection
        "Possible SQL injection via string concatenation. Use parameterised queries."
    ),
    "B611": (  # django sql injection
        "Django ORM .extra() or .raw() with user input is SQL injection. Use ORM filters."
    ),
    "B703": (  # django mark_safe
        "mark_safe() with user input bypasses Django's XSS protection. Never pass user data to mark_safe()."
    ),
}

# Default remediation for anything not in the map above
DEFAULT_REMEDIATION = (
    "Review this finding against the OWASP Top 10 (https://owasp.org/Top10) "
    "and the CWE entry for this weakness type. Apply the principle of least privilege "
    "and validate/sanitise all external input."
)


def get_remediation(rule_id: str) -> str:
    """
    Look up remediation text for a given rule_id or Bandit test_id.
    Falls back to DEFAULT_REMEDIATION if the ID is not in our map.
    """
    return REMEDIATION_MAP.get(rule_id, DEFAULT_REMEDIATION)


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: language → file extension
# ─────────────────────────────────────────────────────────────────────────────

def _lang_to_ext(language: str) -> str:
    """Map a language name to the file extension Semgrep needs to parse it."""
    return {
        "python":     ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "go":         ".go",
        "java":       ".java",
        "ruby":       ".rb",
    }.get(language.lower(), ".txt")


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Normalise code before scanning
# ─────────────────────────────────────────────────────────────────────────────

def normalise_code(code: str) -> str:
    """
    Normalise line endings to LF.

    BACKGROUND: When code arrives as a JSON string, Windows-style CRLF (\\r\\n)
    can survive JSON decoding. Bandit uses Python's tokeniser which counts
    bytes before parsing. CRLF causes Bandit to report "0 bytes" and skip the
    file entirely. We strip and convert before writing to disk.
    """
    return code.strip().replace('\r\n', '\n').replace('\r', '\n')


# ─────────────────────────────────────────────────────────────────────────────
# SEMGREP SCANNER
# ─────────────────────────────────────────────────────────────────────────────

def run_semgrep(code: str, language: str, rules_path: str) -> list[dict]:
    """
    Run Semgrep with our bundled local rules against the provided code.

    SEMGREP OSS CONSTRAINTS (important — read this):
    - Semgrep OSS (the free CLI) can only use rules you provide locally.
    - Rules from the registry (p/python, p/secrets, auto) silently scan 0 files
      unless you have a paid semgrep.dev account with Pro rules enabled.
    - Decision: we ONLY use rules/python-security.yml which we own and ship.
    - No SEMGREP_APP_TOKEN needed or used.
    - --disable-version-check: skips the semgrep.dev version ping on every run,
      keeping scans fully offline and slightly faster.

    RETURNS: list of finding dicts, each with keys:
      rule_id, message, severity, line, col, code_snippet, tool, remediation
    """
    normalised = normalise_code(code)
    suffix = _lang_to_ext(language)
    findings = []

    # NamedTemporaryFile with delete=False so we control cleanup in finally.
    # We assign tmp_path before the try block so the finally clause can always
    # reference it safely (avoids NameError if an exception fires mid-setup).
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as f:
            f.write(normalised)
            tmp_path = f.name

        cmd = [
            "semgrep",
            "--config", rules_path,         # path to our local rules YAML
            "--json",                        # machine-readable output
            "--quiet",                       # suppress progress bars / info
            "--no-git-ignore",               # don't skip files based on .gitignore
            "--disable-version-check",       # no network ping on startup
            tmp_path,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",     # tool output is UTF-8; without this, Windows
            errors="replace",     # decodes as cp1252 and crashes on non-ASCII bytes
            timeout=60,
        )

        # Semgrep exits 0 (no findings) or 1 (findings found) — both valid.
        # Exit 2+ means an error (bad config, parse error, etc.)
        if result.returncode > 1:
            logger.warning(
                "semgrep non-zero exit",
                extra={"returncode": result.returncode, "stderr": result.stderr[:500]}
            )

        if result.stdout.strip():
            output = json.loads(result.stdout)

            for match in output.get("results", []):
                rule_id = match.get("check_id", "unknown")
                # check_id is the full path like "rules/python-security.hardcoded-password"
                # Extract just the last segment for a cleaner rule_id.
                short_rule_id = rule_id.split(".")[-1]

                findings.append({
                    "tool":         "semgrep",
                    "rule_id":      short_rule_id,
                    "message":      match.get("extra", {}).get("message", ""),
                    "severity":     match.get("extra", {}).get("severity", "WARNING"),
                    "line":         match.get("start", {}).get("line", 0),
                    "col":          match.get("start", {}).get("col", 0),
                    "code_snippet": match.get("extra", {}).get("lines", "").strip(),
                    "remediation":  get_remediation(short_rule_id),
                })

    except subprocess.TimeoutExpired:
        logger.error("semgrep timed out after 60s")
    except json.JSONDecodeError as e:
        logger.error("failed to parse semgrep JSON output", extra={"error": str(e)})
    except FileNotFoundError:
        logger.error("semgrep binary not found — is it installed in the Dockerfile?")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    logger.info("semgrep complete", extra={"findings_count": len(findings)})
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# BANDIT SCANNER
# ─────────────────────────────────────────────────────────────────────────────

def run_bandit(code: str) -> list[dict]:
    """
    Run Bandit against the provided Python code.

    BANDIT OVERVIEW:
    - Bandit is a Python-only static analysis tool from PyCQA.
    - It has ~80 built-in tests (B1xx–B7xx) covering imports, crypto, injection, etc.
    - No config or auth needed — fully offline.
    - We run with -l -i (low severity + low confidence) to catch everything.
    - Output: JSON with "results" list.

    BANDIT vs SEMGREP:
    - Bandit has far more Python-specific tests than our Semgrep local rules.
    - Semgrep's strength is custom pattern matching; Bandit's is its test library.
    - Together they provide complementary coverage.

    RETURNS: list of finding dicts (same schema as semgrep findings)
    """
    normalised = normalise_code(code)
    findings = []

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(normalised)
            tmp_path = f.name

        cmd = [
            "bandit",
            "-f", "json",   # output format: JSON
            "-l",            # low severity threshold (catch everything)
            "-i",            # low confidence threshold
            tmp_path,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",     # tool output is UTF-8; without this, Windows
            errors="replace",     # decodes as cp1252 and crashes on non-ASCII bytes
            timeout=60,
        )

        # Bandit exits 0 (no issues), 1 (issues found), or 2 (error).
        # 0 and 1 both produce valid JSON output.
        if result.returncode > 1:
            logger.warning(
                "bandit non-zero exit",
                extra={"returncode": result.returncode, "stderr": result.stderr[:500]}
            )

        if result.stdout.strip():
            output = json.loads(result.stdout)

            for issue in output.get("results", []):
                test_id = issue.get("test_id", "UNKNOWN")

                findings.append({
                    "tool":         "bandit",
                    "rule_id":      test_id,
                    "message":      issue.get("issue_text", ""),
                    "severity":     issue.get("issue_severity", "MEDIUM"),
                    "confidence":   issue.get("issue_confidence", "MEDIUM"),
                    "line":         issue.get("line_number", 0),
                    "code_snippet": issue.get("code", "").strip(),
                    "remediation":  get_remediation(test_id),
                })

    except subprocess.TimeoutExpired:
        logger.error("bandit timed out after 60s")
    except json.JSONDecodeError as e:
        logger.error("failed to parse bandit JSON output", extra={"error": str(e)})
    except FileNotFoundError:
        logger.error("bandit binary not found — is it installed in the Dockerfile?")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    logger.info("bandit complete", extra={"findings_count": len(findings)})
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def scan(code: str, language: str, job_id: str, rules_path: str | None = None) -> dict:
    """
    Orchestrates both scanners and returns a unified findings payload.

    Called by consumer.py after a job is pulled from RabbitMQ.

    Returns a dict that publisher.py will serialise to JSON and push
    to the scan_results queue.

    Args:
        code:       Source code to scan.
        language:   Language string, e.g. "python".
        job_id:     Unique job identifier (passed through to the result payload).
        rules_path: Optional explicit path to the Semgrep rules YAML.
                    If omitted, resolved relative to this file (production default).
                    Pass explicitly in tests so the path doesn't depend on cwd.

    Structure:
    {
        "job_id": "...",
        "language": "python",
        "service": "sast-scanner",
        "total_findings": 3,
        "findings": [
            {
                "tool": "bandit",
                "rule_id": "B301",
                "message": "...",
                "severity": "HIGH",
                "confidence": "HIGH",
                "line": 5,
                "col": 0,
                "code_snippet": "...",
                "remediation": "..."
            },
            ...
        ],
        "rule_coverage": {
            "semgrep_rules_path": "...",
            "semgrep_rules_loaded": true,
            "bandit_enabled": true
        }
    }
    """
    # If no rules_path supplied, resolve relative to this scanner.py file.
    # __file__ is the path of scanner.py; we go up one dir to app/
    # then up again to sast-scanner/ where rules/ lives.
    if rules_path is None:
        rules_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),  # sast-scanner/
            "rules",
            "python-security.yml"
        )

    if not os.path.exists(rules_path):
        logger.error(
            "semgrep rules file not found",
            extra={"expected_path": rules_path}
        )
        rules_path = None

    all_findings = []

    # Run Semgrep if we have rules and it's a supported language
    if rules_path:
        logger.info("starting semgrep scan", extra={"job_id": job_id})
        semgrep_findings = run_semgrep(code, language, rules_path)
        all_findings.extend(semgrep_findings)

    # Run Bandit only for Python (it's Python-only)
    if language.lower() == "python":
        logger.info("starting bandit scan", extra={"job_id": job_id})
        bandit_findings = run_bandit(code)
        all_findings.extend(bandit_findings)

    # Deduplicate: if Bandit and Semgrep both fire on the same line for the
    # same issue (e.g. pickle), keep both — they have different messages
    # and rule IDs so they're genuinely distinct findings.
    # No dedup needed at this stage.

    result = {
        "job_id":          job_id,
        "language":        language,
        "service":         "sast-scanner",
        "total_findings":  len(all_findings),
        "findings":        all_findings,
        "rule_coverage": {
            "semgrep_rules_path":    rules_path or "NOT FOUND",
            "semgrep_rules_loaded":  rules_path is not None,
            "bandit_enabled":        language.lower() == "python",
        }
    }

    logger.info(
        "scan complete",
        extra={
            "job_id":          job_id,
            "total_findings":  len(all_findings),
            "semgrep_count":   len([f for f in all_findings if f["tool"] == "semgrep"]),
            "bandit_count":    len([f for f in all_findings if f["tool"] == "bandit"]),
        }
    )

    return result
