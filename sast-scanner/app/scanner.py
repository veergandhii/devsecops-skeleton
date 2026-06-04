import subprocess
import tempfile
import json
import os

def run_semgrep(code: str, language: str) -> list[dict]:
    suffix = _lang_to_ext(language)

    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
        # Normalize line endings and strip leading whitespace — critical for
        # code arriving via JSON payloads from Windows clients
        f.write(code.strip().replace('\r\n', '\n').replace('\r', '\n'))
        tmp_path = f.name

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config", "/rules/python-security.yml",  # bundled rules, no network
                "--json",
                "--disable-version-check",
                "--no-git-ignore",
                tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        print(f"[semgrep] exit code: {result.returncode}")
        print(f"[semgrep] stderr: {result.stderr[:200]}")

        output = json.loads(result.stdout)
        findings = []
        for r in output.get("results", []):
            findings.append({
                "tool":     "semgrep",
                "rule_id":  r["check_id"],
                "severity": r["extra"]["severity"],
                "message":  r["extra"]["message"],
                "line":     r["start"]["line"],
                "col":      r["start"]["col"],
            })
        return findings

    except subprocess.TimeoutExpired:
        return [{"tool": "semgrep", "error": "timeout"}]
    except json.JSONDecodeError as e:
        return [{"tool": "semgrep", "error": f"json parse failed: {e}", "raw": result.stdout[:500]}]
    finally:
        os.unlink(tmp_path)


def run_bandit(code: str) -> list[dict]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        # Same normalization as semgrep
        f.write(code.strip().replace('\r\n', '\n').replace('\r', '\n'))
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", tmp_path],
            capture_output=True,
            text=True,
            timeout=60,
        )

        print(f"[bandit] exit code: {result.returncode}")

        output = json.loads(result.stdout)
        findings = []
        for r in output.get("results", []):
            findings.append({
                "tool":       "bandit",
                "rule_id":    r["test_id"],
                "severity":   r["issue_severity"],
                "confidence": r["issue_confidence"],
                "message":    r["issue_text"],
                "line":       r["line_number"],
            })
        return findings

    except subprocess.TimeoutExpired:
        return [{"tool": "bandit", "error": "timeout"}]
    except json.JSONDecodeError as e:
        return [{"tool": "bandit", "error": f"json parse failed: {e}", "raw": result.stdout[:500]}]
    finally:
        os.unlink(tmp_path)


def _lang_to_ext(language: str) -> str:
    return {
        "python":     ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "go":         ".go",
        "java":       ".java",
        "ruby":       ".rb",
    }.get(language.lower(), ".txt")