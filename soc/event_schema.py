"""Normalized event schema (a trimmed-down ECS) and timestamp helpers.

Every parser produces dicts of plain fields from this vocabulary, so detection rules can be
written once against a single schema instead of per-vendor log formats.
"""
from __future__ import annotations

import datetime as dt
import re

# Canonical field names. Rules may only reference these (validated in soc/detection.py).
# Canonical field names. This list is the contract between ingestion and detection: the
# normalizer fills every one of these (None when absent) so rules can index freely and so a
# field name typo shows up as "rule never matches" rather than a KeyError deep in the engine.
FIELDS = [
    "@timestamp", "event.dataset", "event.action", "event.outcome", "event.kind", "event.id",
    "event.original",
    "host.name", "host.ip", "host.criticality",
    "user.name", "user.domain",
    "source.ip", "source.port", "source.host", "source.mac",
    "destination.ip", "destination.port", "destination.domain", "destination.nat.ip",
    "url.path", "url.domain", "url.full", "http.request.method", "http.response.status_code",
    "network.bytes", "bytes_sent", "network.direction", "network.transport", "network.packets",
    "process.name", "process.parent", "process.command_line", "process.pid", "process.hash",
    "process.image_raw", "process.access_mask", "access_mask", "target.process",
    "file.path", "file.name", "file.hash", "file.size", "file.new_contents",
    "registry.key", "registry.value",
    "dns.question.name", "dns.rcode", "dns.answer", "query_type", "answer",
    "auth.method", "auth.mfa", "firewall.rule", "firewall.action",
    "file_count", "file_bytes", "file_total",
    "source.ip_not_private", "destination.ip_not_private", "logon.failure", "logon.success",
    "web_auth_failure", "tags", "rule.name",
]

# Fields that are useful to group/deduplicate alerts on.
ENTITY_FIELDS = ["user.name", "host.name", "source.ip", "destination.domain", "process.name"]

TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%a, %d %b %Y %H:%M:%S %z",
    "%a, %d %b %Y %H:%M:%S",
]

_APACHE_TS = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) [^\]]*\]")


def parse_ts(value):
    """Best-effort timestamp parsing. Returns aware datetime (UTC) or None."""
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    # apache style: 02/Sep/2026:09:41:22 (+0530) -> handled by %d/%b/%Y:%H:%M:%S below
    for fmt in TS_FORMATS + ["%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"]:
        try:
            d = dt.datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    m = _APACHE_TS.search(s)
    if m:
        try:
            return dt.datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S").replace(
                tzinfo=dt.timezone.utc)
        except ValueError:
            return None
    # syslog "Sep  2 09:41:22" has no year: assume 2026 (demo dataset)
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", s)
    if m:
        months = {v: i + 1 for i, v in enumerate(
            ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
        try:
            return dt.datetime(2026, months[m.group(1)], int(m.group(2)), int(m.group(3)),
                               int(m.group(4)), int(m.group(5)), tzinfo=dt.timezone.utc)
        except (KeyError, ValueError):
            return None
    return None


def iso(d):
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00") if d else None


def event_ts(event):
    """Return the parsed @timestamp of a normalized event (cached on the dict)."""
    cached = event.get("_ts")
    if isinstance(cached, dt.datetime):
        return cached
    parsed = parse_ts(event.get("@timestamp"))
    event["_ts"] = parsed
    return parsed


def ensure_schema(event):
    """Fill missing canonical fields with None so downstream code can index freely."""
    for f in FIELDS:
        event.setdefault(f, None)
    if not isinstance(event.get("tags"), list):
        event["tags"] = []
    return event
