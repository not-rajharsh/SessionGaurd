import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.events import EventLog
from app.main import create_app
from app.store import MemoryStore

KEY = "test-key"
HEADERS = {"Authorization": f"Bearer {KEY}"}

# Demo geo table: 203.0.113.x = Delhi/AS64500, 198.51.100.x = New York/AS64501
DELHI, DELHI_2, NYC = "203.0.113.10", "203.0.113.77", "198.51.100.20"
UA_A = "Mozilla/5.0 (X11; Linux x86_64) Chrome/130 LegitBrowser"
UA_B = "Mozilla/5.0 (Windows NT 10.0) Firefox/120 Attacker"
FP_A, FP_B = "a" * 64, "b" * 64


@pytest.fixture
def settings(tmp_path):
    return Settings(engine_api_key=KEY, redis_url="", risk_state="memory",
                    sqlite_path=str(tmp_path / "events.db"), state_ttl_seconds=60,
                    max_travel_kmh=900, min_travel_km=100,
                    geo_path="app/data/geo_demo.json")


@pytest.fixture
def events(settings):
    return EventLog(settings.sqlite_path)


@pytest.fixture
def client(settings, events):
    return TestClient(create_app(settings, store=MemoryStore(), events=events))


def body(sid="sess-12345678", ip=DELHI, ua=UA_A, fp=FP_A):
    return {"session_id": sid, "ip": ip, "user_agent": ua, "fingerprint_hash": fp}
