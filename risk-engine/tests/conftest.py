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


# ======================= Phase 2 helpers =======================
import base64  # noqa: E402
from dataclasses import replace  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

SID = "sess-12345678"


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class DeviceKey:
    """Stands in for the browser's non-extractable WebCrypto key."""

    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())

    @property
    def spki(self):
        der = self.priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(der).decode()

    def sign(self, message: str) -> str:  # WebCrypto format: raw r||s, base64url
        r, s = decode_dss_signature(self.priv.sign(message.encode(), ec.ECDSA(hashes.SHA256())))
        return base64.urlsafe_b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).rstrip(b"=").decode()


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def l2(settings, events, clock):
    """App with a controllable clock; `.store` exposes the in-memory state."""
    store = MemoryStore()
    c = TestClient(create_app(settings, store=store, events=events, clock=clock))
    c.store = store
    c.settings = settings
    return c


@pytest.fixture
def make_app(settings, events, clock):
    def _make(**overrides):
        store = MemoryStore()
        c = TestClient(create_app(replace(settings, **{k: v for k, v in overrides.items() if k != "explain_fn"}),
                                  store=store, events=events, clock=clock,
                                  explain_fn=overrides.get("explain_fn")))
        c.store = store
        return c
    return _make


def evaluate(client, sid=SID, ip=DELHI, ua=UA_A, fp=FP_A, kind="read", route="", proof=None):
    payload = {**body(sid, ip, ua, fp), "kind": kind, "route": route}
    if proof:
        payload.update(proof_nonce=proof["nonce"], proof_signature=proof["signature"],
                       proof_purpose=proof["purpose"])
    r = client.post("/evaluate", json=payload, headers=HEADERS)
    assert r.status_code == 200, r.text
    return r.json()


def login_bound(client, key=None, sid=SID, **ctx):
    """What the app does at login: baseline via /evaluate, then /bind."""
    key = key or DeviceKey()
    evaluate(client, sid, **ctx)
    r = client.post("/bind", json={"session_id": sid, "public_key": key.spki}, headers=HEADERS)
    assert r.status_code == 200, r.text
    return key


def proof_for(client, key, purpose, sid=SID):
    n = client.post("/nonce", json={"session_id": sid}, headers=HEADERS).json()["nonce"]
    return {"nonce": n, "signature": key.sign(f"{n}|{purpose}"), "purpose": purpose}


def names(result):
    return {s["name"] for s in result["signals"]}
