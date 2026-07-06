"""models.py — SQLite storage for runs and findings (stdlib sqlite3, no ORM)."""
import sqlite3
import json
from contextlib import contextmanager
from app.config import DB_PATH


@contextmanager
def _conn():
    # check_same_thread=False: FastAPI may touch the DB from different threads.
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row     # rows behave like dicts → easy to template
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create tables on first start. Idempotent (IF NOT EXISTS)."""
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            job_id     TEXT PRIMARY KEY,
            service    TEXT,
            timestamp  TEXT,
            total      INTEGER
        );
        CREATE TABLE IF NOT EXISTS findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id     TEXT,
            tool       TEXT,
            rule_id    TEXT,
            finding_type TEXT,
            severity   TEXT,
            location   TEXT,
            description TEXT,
            recommendation TEXT,
            ai         TEXT      -- the AI block, stored as JSON text
        );
        """)


def save_envelope(envelope: dict):
    """Persist one ai-results envelope: a run row + one row per finding."""
    job_id = envelope.get("job_id", "unknown")
    findings = envelope.get("findings", [])
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO runs(job_id, service, timestamp, total) VALUES (?,?,?,?)",
            (job_id, envelope.get("service", ""), envelope.get("timestamp", ""), len(findings)),
        )
        for f in findings:
            c.execute(
                """INSERT INTO findings
                   (job_id, tool, rule_id, finding_type, severity, location,
                    description, recommendation, ai)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (job_id, f.get("tool"), f.get("rule_id"), f.get("finding_type"),
                 (f.get("severity") or "INFO").upper(), f.get("location"),
                 f.get("description"), f.get("recommendation"),
                 json.dumps(f.get("ai", {}))),
            )


def get_runs(limit: int = 50):
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM runs ORDER BY timestamp DESC LIMIT ?", (limit,))]


def get_findings(severity: str = None, tool: str = None):
    q, args = "SELECT * FROM findings WHERE 1=1", []
    if severity:
        q += " AND severity = ?"; args.append(severity.upper())
    if tool:
        q += " AND tool = ?"; args.append(tool)
    q += " ORDER BY id DESC LIMIT 500"
    with _conn() as c:
        rows = [dict(r) for r in c.execute(q, args)]
    for r in rows:
        r["ai"] = json.loads(r["ai"] or "{}")     # rehydrate the AI block for templates
    return rows


def severity_counts():
    with _conn() as c:
        return {r["severity"]: r["n"] for r in c.execute(
            "SELECT severity, COUNT(*) n FROM findings GROUP BY severity")}