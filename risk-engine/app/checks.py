"""checks: layer (a) deterministic signals. Pure functions, no I/O.

Compares the current request against two reference points for the session:
  * baseline  - what we saw at login (IP, UA, fingerprint, ASN). Never moves.
  * last_seen - the last request that was ALLOWED (used for impossible travel).
    It only advances on allowed requests, so an attacker cannot drag it along.
Each fired check yields a Signal with a fixed weight; scoring.py sums them.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .geo import GeoDB, haversine_km

WEIGHTS = {
    "ip_change": 10,
    "asn_change": 20,
    "user_agent_mismatch": 30,
    "fingerprint_mismatch": 35,
    "impossible_travel": 40,
}


@dataclass(frozen=True)
class Observation:
    ip: str
    user_agent: str
    fingerprint_hash: str
    ts: float  # unix seconds, server clock

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Observation":
        return cls(d["ip"], d["user_agent"], d["fingerprint_hash"], d["ts"])


@dataclass(frozen=True)
class Signal:
    name: str
    weight: int
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def _sig(name: str, detail: str) -> Signal:
    return Signal(name, WEIGHTS[name], detail)


def _short(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def run_checks(
    baseline: Observation,
    last_seen: Observation,
    current: Observation,
    geo: GeoDB,
    *,
    max_kmh: float = 900.0,
    min_km: float = 100.0,
) -> list[Signal]:
    signals: list[Signal] = []
    base_geo = geo.lookup(baseline.ip)
    last_geo = geo.lookup(last_seen.ip)
    cur_geo = geo.lookup(current.ip)

    if current.ip != baseline.ip:
        signals.append(_sig("ip_change", f"{baseline.ip} -> {current.ip}"))

    if base_geo and cur_geo and base_geo.asn != cur_geo.asn:
        signals.append(
            _sig(
                "asn_change",
                f"AS{base_geo.asn} ({base_geo.asn_org}) -> AS{cur_geo.asn} ({cur_geo.asn_org})",
            )
        )

    if current.user_agent != baseline.user_agent:
        signals.append(
            _sig(
                "user_agent_mismatch",
                f"'{_short(baseline.user_agent)}' -> '{_short(current.user_agent)}'",
            )
        )

    if current.fingerprint_hash != baseline.fingerprint_hash:
        signals.append(
            _sig(
                "fingerprint_mismatch",
                f"{baseline.fingerprint_hash[:12]} -> {current.fingerprint_hash[:12]}",
            )
        )

    if last_geo and cur_geo:
        km = haversine_km(last_geo.lat, last_geo.lon, cur_geo.lat, cur_geo.lon)
        elapsed = max(current.ts - last_seen.ts, 1.0)  # floor at 1s
        kmh = km / (elapsed / 3600.0)
        if km >= min_km and kmh > max_kmh:
            when = f"{elapsed:.0f}s" if elapsed < 120 else f"{elapsed / 60:.0f} min"
            speed = f"{kmh:,.0f}" if kmh < 100_000 else ">100,000"
            signals.append(
                _sig(
                    "impossible_travel",
                    f"{last_geo.city} -> {cur_geo.city}: {km:,.0f} km in {when} "
                    f"(needs {speed} km/h, limit {max_kmh:.0f})",
                )
            )
    return signals
