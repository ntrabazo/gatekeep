"""Audit trail: SQLite (WAL), one row per request decision.

NEVER-LOG RULE: raw prompt/secret text is never stored — only hashes, categories,
detector names, span-derived previews stay out entirely (not even previews land here).
"""

import sqlite3
import threading
from dataclasses import asdict, dataclass
from typing import Optional

DB_PATH = "audit.db"

_conn: Optional[sqlite3.Connection] = None
_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc          TEXT NOT NULL,
    action          TEXT NOT NULL,   -- allow | redact | block | reject_stream
    categories      TEXT,            -- csv, e.g. "pii,secret"
    detectors       TEXT,            -- csv, e.g. "aws_access_key,ssn" (+ "scan_truncated")
    prompt_sha256   TEXT,            -- sha256 of all extracted texts concatenated, PRE-redaction
    model_requested TEXT,
    model_routed    TEXT,            -- NULL when no upstream call (block / reject_stream)
    status_upstream INTEGER,         -- NULL when no upstream call
    latency_ms      REAL
)
"""


@dataclass
class AuditEvent:
    ts_utc: str
    action: str
    categories: str
    detectors: str
    prompt_sha256: str
    model_requested: Optional[str]
    model_routed: Optional[str]
    status_upstream: Optional[int]
    latency_ms: float


def init_db(path: str = DB_PATH) -> None:
    global _conn
    _conn = sqlite3.connect(path, check_same_thread=False)
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute(_SCHEMA)
    _conn.commit()


def log_event(event: AuditEvent) -> None:
    fields = asdict(event)
    columns = ", ".join(fields)
    placeholders = ", ".join(":" + k for k in fields)
    with _lock:
        _conn.execute(f"INSERT INTO audit_events ({columns}) VALUES ({placeholders})", fields)
        _conn.commit()


def query_events(action: Optional[str] = None, since: Optional[str] = None, limit: int = 100) -> list[dict]:
    sql = "SELECT * FROM audit_events WHERE 1=1"
    params: list = []
    if action:
        sql += " AND action = ?"
        params.append(action)
    if since:
        sql += " AND ts_utc >= ?"  # ISO-8601 UTC strings compare lexicographically
        params.append(since)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with _lock:
        cur = _conn.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
