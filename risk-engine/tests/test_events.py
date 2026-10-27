"""Tests for events: SQLite log records and returns signals."""
from app.checks import Signal
from app.events import EventLog


def test_record_and_recent(tmp_path):
    log = EventLog(str(tmp_path / "sub" / "e.db"))
    log.record(session_id="s1", ip="1.2.3.4", user_agent="ua", fingerprint_hash="fp",
               score=40, action="challenge", signals=[Signal("ip_change", 10, "a -> b")])
    (row,) = log.recent()
    assert row["session_id"] == "s1" and row["action"] == "challenge"
    assert row["signals"][0]["name"] == "ip_change"


def test_old_database_is_migrated_and_rationale_roundtrips(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.db")
    c = sqlite3.connect(path)  # Phase 1 schema, no route/rationale columns
    c.execute("""CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, session_id TEXT NOT NULL,
      ip TEXT NOT NULL, user_agent TEXT NOT NULL, fingerprint_hash TEXT NOT NULL, score INTEGER NOT NULL,
      action TEXT NOT NULL, signals TEXT NOT NULL)""")
    c.commit(); c.close()
    log = EventLog(path)
    eid = log.record(session_id="s", ip="1.2.3.4", user_agent="u", fingerprint_hash="f", score=0,
                     action="allow", signals=[], route="GET /x")
    log.set_rationale(eid, "because", "template")
    assert log.get(eid)["rationale"] == "because" and log.get(eid)["route"] == "GET /x"
