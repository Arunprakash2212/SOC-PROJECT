"""Tiny offline geolocation helper (in a real SOC this is GeoLite2 + a VPN/anonymizer list)."""
from __future__ import annotations

import ipaddress

# prefix -> (label, lat, lon). Longest prefix wins. Deliberately small: enough to make
# "impossible travel" work end to end without shipping a 60 MB database.
NETWORKS = [
    ("10.0.0.0/8", ("Coimbatore, IN (corporate LAN)", 11.0168, 76.9558)),
    ("103.216.220.0/24", ("Chennai, IN", 13.0827, 80.2707)),
    ("104.28.55.0/24", ("Singapore, SG", 1.3521, 103.8198)),
    ("45.155.205.0/24", ("Frankfurt, DE (anonymizer)", 50.1109, 8.6821)),
    ("185.220.101.0/24", ("Rotterdam, NL (anonymizer)", 51.9244, 4.4777)),
    ("203.0.113.0/24", ("Johannesburg, ZA", -26.2041, 28.0473)),
    ("198.51.100.0/24", ("Sao Paulo, BR", -23.5505, -46.6333)),
    ("192.0.2.0/24", ("Ashburn US (bulletproof hosting)", 39.0438, -77.4874)),
    ("13.107.42.0/24", ("Redmond, US", 47.6740, -122.1215)),
]

CATEGORIES = {
    "45.155.205.0/24": "anonymizer",
    "185.220.101.0/24": "anonymizer",
    "192.0.2.0/24": "hosting-provider",
    "10.0.0.0/8": "private",
}

_cache = {}


INTERNAL_NETS = [ipaddress.ip_network(c) for c in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                  "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7")]


def is_private(ip):
    """RFC1918/loopback only.

    Deliberately NOT ``ipaddress.ip_address(x).is_private``: Python's notion of "private" also
    covers IETF reserved ranges (TEST-NET 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
    benchmarking 198.18.0.0/15), so a SOC that trusts it silently treats attacker IPs from
    documentation space as internal and never alerts. That is exactly the class of bug that
    kills a "not internal" filter in production.
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETS)


def locate(ip):
    """-> {"ip", "label", "coords", "category", "private"} or None when the IP is unknown."""
    if not ip:
        return None
    ip = str(ip).strip()
    if ip in _cache:
        return _cache[ip]
    out = None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        out = {"ip": ip, "label": f"unparsed ({ip})", "coords": None, "category": None,
               "private": False}
        _cache[ip] = out
        return out
    best = None
    for prefix, meta in NETWORKS:
        net = ipaddress.ip_network(prefix)
        if addr in net:
            if best is None or net.prefixlen > best[0]:
                best = (net.prefixlen, meta, prefix)
    label, coords = (best[1][0], (best[1][1], best[1][2])) if best else (None, None)
    category = CATEGORIES.get(best[2]) if best else None
    out = {"ip": ip,
           "label": label or ("private range" if addr.is_private else f"unknown ({ip})"),
           "coords": coords, "category": category, "private": addr.is_private}
    _cache[ip] = out
    return out
