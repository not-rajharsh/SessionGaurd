"""checks: layer (a) deterministic signals. Pure functions, no I/O.

Compares the current request against two reference points for the session:
  * baseline  - what we saw at login (IP, UA, fingerprint, ASN). Never moves.
  * last_seen - the last request that was ALLOWED (used for impossible travel).
    It only advances on allowed requests, so an attacker cannot drag it along.
Each fired check yields a Signal with a fixed weight; scoring.py sums them.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .geo import GeoDB, haversine_km

WEIGHTS = {
    # --- layer 1: deterministic checks
    "ip_change": 10,
    "asn_change": 20,
    "user_agent_mismatch": 30,
    # WEAK SIGNAL. The Phase 1 fingerprint is a hash of request headers
    # (Accept-Language, Accept-Encoding, sec-ch-ua-platform). An attacker who has
    # seen the victim's traffic, or simply copies the headers, reproduces it
    # exactly, so a *match* proves nothing. Only a mismatch is mildly informative
    # (lazy attackers), hence the low weight (was 35 in Phase 1).
    "fingerprint_mismatch": 10,
    "impossible_travel": 40,
    # --- layer 2: device-bound key (proof of possession)
    "proof_valid": -25,     # strongly lowers the score: the device key just signed
    "proof_stale": 35,      # read with no device proof in the last 30 s -> step-up
    "proof_missing": 50,    # state-changing request without its own proof -> step-up
    "proof_expired": 50,    # nonce unknown / expired / already used -> step-up
    "proof_invalid": 80,    # wrong key or wrong purpose: forged proof -> terminate
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
    # Raw structured facts behind the signal. This (never `detail`, which is prose
    # built from request values) is what explain() sanitises and sends to an LLM.
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _sig(name: str, detail: str, **data) -> Signal:
    return Signal(name, WEIGHTS[name], detail, data)


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
        signals.append(_sig("ip_change", f"{baseline.ip} -> {current.ip}",
                            baseline_ip=baseline.ip, current_ip=current.ip))

    if base_geo and cur_geo and base_geo.asn != cur_geo.asn:
        signals.append(
            _sig(
                "asn_change",
                f"AS{base_geo.asn} ({base_geo.asn_org}) -> AS{cur_geo.asn} ({cur_geo.asn_org})",
                baseline_asn=base_geo.asn, current_asn=cur_geo.asn,
            )
        )

    if current.user_agent != baseline.user_agent:
        signals.append(
            _sig(
                "user_agent_mismatch",
                f"'{_short(baseline.user_agent)}' -> '{_short(current.user_agent)}'",
                baseline_user_agent=baseline.user_agent, current_user_agent=current.user_agent,
            )
        )

    if current.fingerprint_hash != baseline.fingerprint_hash:
        signals.append(
            _sig(
                "fingerprint_mismatch",
                f"{baseline.fingerprint_hash[:12]} -> {current.fingerprint_hash[:12]}",
                baseline_fingerprint=baseline.fingerprint_hash[:12],
                current_fingerprint=current.fingerprint_hash[:12],
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
                    from_city=last_geo.city, to_city=cur_geo.city, km=round(km),
                    seconds=round(elapsed), limit_kmh=round(max_kmh),
                )
            )
    return signals
