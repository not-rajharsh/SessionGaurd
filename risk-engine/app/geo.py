"""geo: offline IP -> (ASN, city, lat/lon) lookup plus haversine distance.

Phase 1 ships a tiny demo table (RFC 5737 documentation ranges, RFC 6996-style
private ASNs) so the demo needs no network or GeoIP license. To go to
production, keep the GeoDB.lookup() interface and back it with MaxMind GeoLite2.
Unknown IPs return None; checks that need geo data simply skip.
"""
from __future__ import annotations

import ipaddress
import json
import math
from dataclasses import dataclass


@dataclass(frozen=True)
class GeoInfo:
    asn: int
    asn_org: str
    city: str
    country: str
    lat: float
    lon: float


class GeoDB:
    def __init__(self, entries: list[dict]):
        nets = [
            (
                ipaddress.ip_network(e["cidr"]),
                GeoInfo(e["asn"], e["asn_org"], e["city"], e["country"], e["lat"], e["lon"]),
            )
            for e in entries
        ]
        # Longest prefix wins.
        self._nets = sorted(nets, key=lambda n: n[0].prefixlen, reverse=True)

    @classmethod
    def from_json(cls, path: str) -> "GeoDB":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    def lookup(self, ip: str) -> GeoInfo | None:
        addr = ipaddress.ip_address(ip)
        for net, info in self._nets:
            if addr.version == net.version and addr in net:
                return info
        return None


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi, dlmb = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))
