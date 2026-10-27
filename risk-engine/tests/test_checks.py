"""Tests for checks: each layer (a) signal fires only when it should."""
from app.checks import Observation, run_checks
from app.geo import GeoDB
from conftest import DELHI, DELHI_2, FP_A, FP_B, NYC, UA_A, UA_B

GEO = GeoDB.from_json("app/data/geo_demo.json")


def obs(ip=DELHI, ua=UA_A, fp=FP_A, ts=1000.0):
    return Observation(ip, ua, fp, ts)


def names(signals):
    return {s.name for s in signals}


def test_identical_context_fires_nothing():
    base = obs()
    assert run_checks(base, base, obs(ts=1060), GEO) == []


def test_ip_change_same_asn_only_ip_signal():
    s = run_checks(obs(), obs(), obs(ip=DELHI_2, ts=1060), GEO)
    assert names(s) == {"ip_change"}


def test_user_agent_and_fingerprint_mismatch():
    s = run_checks(obs(), obs(), obs(ua=UA_B, fp=FP_B, ts=1060), GEO)
    assert names(s) == {"user_agent_mismatch", "fingerprint_mismatch"}


def test_asn_change_and_impossible_travel():
    s = run_checks(obs(), obs(), obs(ip=NYC, ts=1060), GEO)
    assert names(s) == {"ip_change", "asn_change", "impossible_travel"}


def test_slow_travel_is_not_impossible():
    # Delhi -> NYC (~11,700 km) after 24h is ~490 km/h: plausible by air.
    s = run_checks(obs(), obs(), obs(ip=NYC, ts=1000 + 24 * 3600), GEO)
    assert "impossible_travel" not in names(s)


def test_unknown_geo_skips_geo_checks():
    s = run_checks(obs(), obs(), obs(ip="8.8.8.8", ts=1001), GEO)
    assert names(s) == {"ip_change"}


def test_travel_measured_from_last_seen_not_baseline():
    # Baseline in Delhi, but last allowed request was already in NYC a day ago.
    last = obs(ip=NYC, ts=1000)
    s = run_checks(obs(), last, obs(ip=NYC, ts=1000 + 3600), GEO)
    assert "impossible_travel" not in names(s)
