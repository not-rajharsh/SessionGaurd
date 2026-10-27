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
