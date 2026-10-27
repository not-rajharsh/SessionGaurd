"""store: live per-session state (baseline, last_seen, terminated flag).

RedisStore is the real backend. MemoryStore exists for tests / RISK_STATE=memory
and ignores TTLs. Both share the JSON (de)serialisation in _KVStore.
A terminated session stays terminated: we never delete its record, otherwise
the next request would silently become a fresh baseline for the attacker.
"""
from __future__ import annotations

import json

import redis

from .checks import Observation


class _KVStore:
    def __init__(self, ttl_seconds: int):
        self.ttl = ttl_seconds

    def _get(self, key: str) -> str | None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _set(self, key: str, value: str) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _obs(self, key: str) -> Observation | None:
        raw = self._get(key)
        return Observation.from_dict(json.loads(raw)) if raw else None

    def get_baseline(self, sid: str) -> Observation | None:
        return self._obs(f"risk:baseline:{sid}")

    def set_baseline(self, sid: str, obs: Observation) -> None:
        self._set(f"risk:baseline:{sid}", json.dumps(obs.to_dict()))

    def get_last_seen(self, sid: str) -> Observation | None:
        return self._obs(f"risk:last:{sid}")

    def set_last_seen(self, sid: str, obs: Observation) -> None:
        self._set(f"risk:last:{sid}", json.dumps(obs.to_dict()))

    def mark_terminated(self, sid: str) -> None:
        self._set(f"risk:terminated:{sid}", "1")

    def is_terminated(self, sid: str) -> bool:
        return self._get(f"risk:terminated:{sid}") is not None


class MemoryStore(_KVStore):
    def __init__(self, ttl_seconds: int = 3600):
        super().__init__(ttl_seconds)
        self._d: dict[str, str] = {}

    def _get(self, key):
        return self._d.get(key)

    def _set(self, key, value):
        self._d[key] = value


class RedisStore(_KVStore):
    def __init__(self, url: str, ttl_seconds: int = 3600):
        super().__init__(ttl_seconds)
        self._r = redis.Redis.from_url(url, decode_responses=True)

    def _get(self, key):
        return self._r.get(key)

    def _set(self, key, value):
        self._r.set(key, value, ex=self.ttl)

    def ping(self) -> bool:
        return bool(self._r.ping())
