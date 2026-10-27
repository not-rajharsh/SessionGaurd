"""Tests for geo: lookup, longest-prefix match, haversine."""
from app.geo import GeoDB, haversine_km


def test_lookup_known_and_unknown():
    db = GeoDB.from_json("app/data/geo_demo.json")
    assert db.lookup("203.0.113.5").city == "Delhi"
    assert db.lookup("198.51.100.9").asn == 64501
    assert db.lookup("8.8.8.8") is None
    assert db.lookup("2001:db8::1") is None


def test_longest_prefix_wins():
    db = GeoDB([
        {"cidr": "10.0.0.0/8", "asn": 1, "asn_org": "wide", "city": "A", "country": "X", "lat": 0, "lon": 0},
        {"cidr": "10.1.0.0/16", "asn": 2, "asn_org": "narrow", "city": "B", "country": "X", "lat": 0, "lon": 0},
    ])
    assert db.lookup("10.1.2.3").asn == 2
    assert db.lookup("10.2.2.3").asn == 1


def test_haversine_delhi_nyc():
    km = haversine_km(28.6139, 77.2090, 40.7128, -74.0060)
    assert 11600 < km < 11900
    assert haversine_km(1, 1, 1, 1) == 0
