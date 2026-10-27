"""Tests for config: env overrides and the refusal to start without a key."""
import pytest

from app.config import get_settings
from app.main import create_app


def test_env_override(monkeypatch):
    monkeypatch.setenv("STATE_TTL_SECONDS", "42")
    monkeypatch.setenv("RISK_STATE", "memory")
    assert get_settings().state_ttl_seconds == 42


def test_engine_refuses_to_start_without_key(monkeypatch):
    monkeypatch.setenv("ENGINE_API_KEY", "")
    with pytest.raises(RuntimeError):
        create_app(get_settings())
