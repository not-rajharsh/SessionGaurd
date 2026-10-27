"""main: FastAPI risk engine. POST /evaluate -> {score, signals, action}.

Flow per call:
  1. Terminated session?  -> terminate immediately.
  2. No baseline yet?     -> this is the login call from the demo app; store it
                             as baseline (trust-on-first-use) and allow.
  3. Otherwise run layer (a) checks vs baseline / last_seen, score, decide.
  4. Only ALLOWED requests advance last_seen; terminate marks the session dead.
  5. Every evaluation is appended to the SQLite event log.
Callers must send `Authorization: Bearer $ENGINE_API_KEY`.
Run: uvicorn --factory app.main:create_app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import hmac
import ipaddress
import logging
import time
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

from .checks import Observation, Signal, run_checks
from .config import Settings, get_settings
from .events import EventLog
from .geo import GeoDB
from .scoring import decide
from .store import MemoryStore, RedisStore

log = logging.getLogger("risk")


class EvaluateRequest(BaseModel):
    session_id: str = Field(min_length=8, max_length=256)
    ip: str
    user_agent: str = Field(max_length=1024)
    fingerprint_hash: str = Field(min_length=1, max_length=128)

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        return str(ipaddress.ip_address(v))  # raises ValueError -> 422


class SignalOut(BaseModel):
    name: str
    weight: int
    detail: str


class EvaluateResponse(BaseModel):
    score: int
    signals: list[SignalOut]
    action: Literal["allow", "challenge", "terminate"]


def create_app(settings: Settings | None = None, store=None, geo: GeoDB | None = None,
               events: EventLog | None = None) -> FastAPI:
    s = settings or get_settings()
    if not s.engine_api_key:
        raise RuntimeError("ENGINE_API_KEY is not set (see .env.example)")
    store = store or (
        MemoryStore(s.state_ttl_seconds) if s.risk_state == "memory"
        else RedisStore(s.redis_url, s.state_ttl_seconds)
    )
    geo = geo or GeoDB.from_json(s.geo_path)
    events = events or EventLog(s.sqlite_path)
    app = FastAPI(title="session-guard risk engine")

    def require_key(authorization: str = Header(default="")):
        if not hmac.compare_digest(authorization, f"Bearer {s.engine_api_key}"):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/evaluate", response_model=EvaluateResponse, dependencies=[Depends(require_key)])
    def evaluate(req: EvaluateRequest):
        sid = req.session_id
        cur = Observation(req.ip, req.user_agent, req.fingerprint_hash, time.time())

        def finish(score: int, action: str, signals: list[Signal]) -> EvaluateResponse:
            events.record(session_id=sid, ip=cur.ip, user_agent=cur.user_agent,
                          fingerprint_hash=cur.fingerprint_hash, score=score, action=action,
                          signals=signals)
            if action == "terminate":
                log.warning("ALERT session=%s score=%d signals=%s", sid, score,
                            [x.name for x in signals])
            return EvaluateResponse(score=score, action=action,
                                    signals=[SignalOut(**x.to_dict()) for x in signals])

        if store.is_terminated(sid):
            return finish(100, "terminate",
                          [Signal("session_terminated", 100, "session was already terminated")])

        baseline = store.get_baseline(sid)
        if baseline is None:
            store.set_baseline(sid, cur)
            store.set_last_seen(sid, cur)
            return finish(0, "allow", [])

        last_seen = store.get_last_seen(sid) or baseline
        signals = run_checks(baseline, last_seen, cur, geo,
                             max_kmh=s.max_travel_kmh, min_km=s.min_travel_km)
        score, action = decide(signals)
        if action == "allow":
            store.set_last_seen(sid, cur)
        elif action == "terminate":
            store.mark_terminated(sid)
        return finish(score, action, signals)

    return app
