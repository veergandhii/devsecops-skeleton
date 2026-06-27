"""
github_client.py — turn an enriched ai-results envelope into ONE Markdown PR comment
and post it via PyGithub. Never raises to the caller (a GitHub outage shouldn't crash
the consumer); logs and returns False on failure.
"""

import logging
from github import Github, Auth, GithubException

from app.config import GITHUB_TOKEN, GITHUB_REPO

logger = logging.getLogger(__name__)

# Emoji per severity — makes the comment scannable at a glance.
_SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}


def build_comment(envelope: dict) -> str:
    """Render the enriched envelope as a single Markdown comment body."""
    findings = envelope.get("findings", [])
    job_id   = envelope.get("job_id", "unknown")

    if not findings:
        return f"## ✅ CodeSheriff: no security findings\nJob `{job_id}` scanned clean."

    # Summary table
    lines = [
        "## 🛡️ CodeSheriff Security Report",
        f"Job `{job_id}` — **{len(findings)} finding(s)**\n",
        "| Sev | Tool | Rule | Location |",
        "|-----|------|------|----------|",
    ]
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        lines.append(
            f"| {_SEV_ICON.get(sev,'⬜')} {sev} | {f.get('tool','?')} | "
            f"`{f.get('rule_id','?')}` | {f.get('location','?')} |"
        )

    # Detail per finding, using the AI block from Phase 6
    lines.append("\n---\n")
    for f in findings:
        ai = f.get("ai", {})
        sev = f.get("severity", "INFO").upper()
        lines += [
            f"### {_SEV_ICON.get(sev,'⬜')} {f.get('rule_id','?')} — {f.get('description','')}",
            f"**Where:** `{f.get('location','?')}`  ·  **Tool:** {f.get('tool','?')}\n",
            f"**What it is:** {ai.get('explanation', f.get('description',''))}\n",
            f"**AI severity:** {ai.get('severity_rating','—')}\n",
            f"**How to fix:**\n{ai.get('remediation', f.get('recommendation','—'))}\n",
            f"📚 Reference: {ai.get('cwe','—')}\n",
        ]
    lines.append("\n_Posted automatically by CodeSheriff._")
    return "\n".join(lines)


def post_comment(envelope: dict) -> bool:
    """Post the built comment to the PR named in envelope.meta (or GITHUB_REPO fallback)."""
    if not GITHUB_TOKEN:
        logger.error("no GITHUB_TOKEN set — cannot post comment")
        return False

    meta      = envelope.get("meta", {}) or {}
    repo_name = meta.get("repo") or GITHUB_REPO
    pr_number = meta.get("pr_number")

    if not repo_name or not pr_number:
        logger.warning("missing repo/pr_number (repo=%s pr=%s) — skipping comment",
                       repo_name, pr_number)
        return False

    try:
        gh   = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = gh.get_repo(repo_name)
        pr   = repo.get_pull(int(pr_number))
        pr.create_issue_comment(build_comment(envelope))
        logger.info("posted comment to %s PR #%s", repo_name, pr_number)
        return True
    except GithubException as e:
        logger.error("GitHub API error (%s): %s", getattr(e, "status", "?"), e)
        return False
    except Exception as e:
        logger.error("failed to post comment: %s", e)
        return False