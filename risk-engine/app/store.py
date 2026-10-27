"""store: live per-session state (baseline, last_seen, terminated flag, device
binding, last proof time, single-use nonces, step-up pending/elevated).

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

    def _set(self, key: str, value: str, ttl: int | None = None) -> None:  # pragma: no cover
        raise NotImplementedError

    def _set_nx(self, key: str, value: str) -> bool:  # pragma: no cover - atomic set-if-absent
        raise NotImplementedError

    def _pop(self, key: str) -> str | None:  # pragma: no cover - atomic get+delete
        raise NotImplementedError

    def _del(self, key: str) -> None:  # pragma: no cover
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

    # --- layer 2: device binding (set once, never overwritten) -------------------
    def get_binding(self, sid: str) -> str | None:
        return self._get(f"risk:bind:{sid}")

    def set_binding(self, sid: str, spki_b64: str) -> bool:
        """Atomic set-if-absent. False means the session was already bound."""
        return self._set_nx(f"risk:bind:{sid}", spki_b64)

    def get_last_proof(self, sid: str) -> float | None:
        raw = self._get(f"risk:proof:{sid}")
        return float(raw) if raw else None

    def set_last_proof(self, sid: str, ts: float) -> None:
        self._set(f"risk:proof:{sid}", repr(ts))

    def put_nonce(self, nonce: str, sid: str, exp: float, ttl: int) -> None:
        self._set(f"risk:nonce:{nonce}", json.dumps({"sid": sid, "exp": exp}), ttl)

    def pop_nonce(self, nonce: str) -> dict | None:
        """Single use: the nonce is gone after this call, valid or not."""
        raw = self._pop(f"risk:nonce:{nonce}")
        return json.loads(raw) if raw else None

    # --- passkey step-up -------------------------------------------------------------
    def get_elevated_until(self, sid: str) -> float:
        raw = self._get(f"risk:elevated:{sid}")
        return float(raw) if raw else 0.0

    def set_elevated_until(self, sid: str, ts: float) -> None:
        self._set(f"risk:elevated:{sid}", repr(ts))

    def get_stepup_pending(self, sid: str) -> float | None:
        raw = self._get(f"risk:pending:{sid}")
        return float(raw) if raw else None

    def set_stepup_pending(self, sid: str, ts: float) -> None:
        self._set(f"risk:pending:{sid}", repr(ts))

    def clear_stepup_pending(self, sid: str) -> None:
        self._del(f"risk:pending:{sid}")


class MemoryStore(_KVStore):
    def __init__(self, ttl_seconds: int = 3600):
        super().__init__(ttl_seconds)
        self._d: dict[str, str] = {}

    def _get(self, key):
        return self._d.get(key)

    def _set(self, key, value, ttl=None):
        self._d[key] = value

    def _set_nx(self, key, value):
        return self._d.setdefault(key, value) is value

    def _pop(self, key):
        return self._d.pop(key, None)

    def _del(self, key):
        self._d.pop(key, None)


class RedisStore(_KVStore):
    def __init__(self, url: str, ttl_seconds: int = 3600):
        super().__init__(ttl_seconds)
        self._r = redis.Redis.from_url(url, decode_responses=True)

    def _get(self, key):
        return self._r.get(key)

    def _set(self, key, value, ttl=None):
        self._r.set(key, value, ex=ttl or self.ttl)

    def _set_nx(self, key, value):
        return bool(self._r.set(key, value, ex=self.ttl, nx=True))

    def _pop(self, key):
        return self._r.getdel(key)

    def _del(self, key):
        self._r.delete(key)

    def ping(self) -> bool:
        return bool(self._r.ping())
