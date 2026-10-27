"""config: environment-driven settings.

Loads ../.env (repo root) if present, then reads os.environ at call time so
tests can override values. Secrets are never defaulted: ENGINE_API_KEY must be
set explicitly or the engine refuses to start.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    engine_api_key: str
    redis_url: str
    risk_state: str  # "redis" (default) or "memory" (tests only)
    sqlite_path: str
    state_ttl_seconds: int
    max_travel_kmh: float
    min_travel_km: float
    geo_path: str


def get_settings() -> Settings:
    return Settings(
        engine_api_key=os.environ.get("ENGINE_API_KEY", ""),
        redis_url=os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"),
        risk_state=os.environ.get("RISK_STATE", "redis"),
        sqlite_path=os.environ.get("SQLITE_PATH", str(ROOT / "data" / "events.db")),
        state_ttl_seconds=int(os.environ.get("STATE_TTL_SECONDS", "3600")),
        max_travel_kmh=float(os.environ.get("MAX_TRAVEL_KMH", "900")),
        min_travel_km=float(os.environ.get("MIN_TRAVEL_KM", "100")),
        geo_path=os.environ.get(
            "GEO_DB_PATH", str(Path(__file__).parent / "data" / "geo_demo.json")
        ),
    )
