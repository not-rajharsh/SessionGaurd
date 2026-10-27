"""events: append-only SQLite log of every evaluation (and terminate alerts).

One short-lived connection per call keeps it safe under FastAPI's threadpool.
The dashboard (later phase) will read from this table.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .checks import Signal

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  session_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  fingerprint_hash TEXT NOT NULL,
  score INTEGER NOT NULL,
  action TEXT NOT NULL,
  signals TEXT NOT NULL
)"""


class EventLog:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def record(self, *, session_id, ip, user_agent, fingerprint_hash, score, action,
               signals: list[Signal]) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO events (ts, session_id, ip, user_agent, fingerprint_hash,"
                " score, action, signals) VALUES (?,?,?,?,?,?,?,?)",
                (time.time(), session_id, ip, user_agent, fingerprint_hash, score, action,
                 json.dumps([s.to_dict() for s in signals])),
            )

    def recent(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "signals": json.loads(r["signals"])} for r in rows]
