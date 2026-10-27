"""Tests for store: baseline/last_seen/terminated roundtrip (memory + Redis if up)."""
import uuid

import pytest
import redis

from app.checks import Observation
from app.store import MemoryStore, RedisStore

OBS = Observation("203.0.113.1", "ua", "fp", 1.0)


def _redis_up():
    try:
        return redis.Redis.from_url("redis://127.0.0.1:6379/0").ping()
    except Exception:
        return False


@pytest.fixture(params=["memory", "redis"])
def store(request):
    if request.param == "memory":
        return MemoryStore()
    if not _redis_up():
        pytest.skip("redis not running")
    return RedisStore("redis://127.0.0.1:6379/0", ttl_seconds=30)


def test_roundtrip(store):
    sid = f"t-{uuid.uuid4()}"
    assert store.get_baseline(sid) is None and not store.is_terminated(sid)
    store.set_baseline(sid, OBS)
    store.set_last_seen(sid, OBS)
    store.mark_terminated(sid)
    assert store.get_baseline(sid) == OBS
    assert store.get_last_seen(sid) == OBS
    assert store.is_terminated(sid)
