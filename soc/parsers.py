"""Log ingestion: raw vendor files -> one normalized event stream.

Four input shapes are supported, because a real SOC's first problem is always "every vendor
invented its own format":

* ``jsonl``  - one JSON object per line (Sysmon-ish, proxy)
* ``apache`` - Apache/Nginx combined log format
* ``csv``    - delimited file with header (firewall, DNS/TSV)
* ``syslog`` - ``Mon DD HH:MM:SS host prog[pid]: key=value ...`` (auth.log)

Two design decisions matter here:

1. **Field aliasing happens at ingest, not in the rules.** Vendor field names are mapped into the
   normalized schema once, so a detection is written a single time and works across all sources.
2. **Nothing is swallowed.** A malformed line becomes a counted parse error; ingestion loss is
   reported on every run, because silent parsing failure = a blind spot nobody knows about.
"""
from __future__ import annotations

import csv
import io
import json
import re

from .event_schema import FIELDS, ensure_schema, iso, parse_ts
from .geo import is_private

APACHE_RE = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>-|\d+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
KV_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"|(\w+)=([^\s"]+)')
SYSLOG_RE = re.compile(r'^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) '
                       r'(?P<prog>[\w\-\.]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$')

# ---------------------------------------------------------------- vendor field -> schema field
ALIASES = {
    "Sysmon": {
        "Computer": "host.name", "SourceComputerName": "host.name", "HostName": "host.name",
        "TargetUserName": "user.name", "User": "user.name", "Account": "user.name",
        "IpAddress": "source.ip", "SourceIp": "source.ip", "ClientIP": "source.ip",
        "Workstation": "source.host", "Image": "process.name", "ProcessName": "process.name",
        "ParentImage": "process.parent", "CommandLine": "process.command_line",
        "TargetFilename": "file.path", "TargetObject": "registry.key",
        "Details": "registry.value", "GrantedAccess": "access_mask",
        "TargetImage": "target.process", "DestinationIp": "destination.ip",
        "DestinationPort": "destination.port", "DestinationHostname": "destination.domain",
        "QueryName": "dns.question.name", "Initiated": "network.direction",
        "NewFileContents": "file.new_contents", "Process": "process.image_raw",
    },
    "Apache": {"client_ip": "source.ip", "bytes": "network.bytes",
               "status": "http.response.status_code", "cs-username": "user.name"},
    "Firewall": {"action": "event.action", "src_ip": "source.ip", "src_port": "source.port",
                 "dst_ip": "destination.ip", "dst_port": "destination.port",
                 "bytes": "network.bytes", "proto": "network.transport", "rule": "firewall.rule",
                 "host": "host.name", "dst_domain": "destination.domain",
                 "user": "user.name", "bytes_sent": "bytes_sent"},
    "DNS": {"client_ip": "source.ip", "host": "host.name", "query": "dns.question.name",
            "type": "query_type", "response_bytes": "network.bytes", "rcode": "dns.rcode",
            "answer": "answer"},
    "Proxy": {},
    "SSH": {"action": "event.action", "ip": "source.ip", "user": "user.name",
            "rport": "source.port", "host": "host.name", "method": "auth.method",
            "outcome": "event.outcome"},
}

# Fields that must hold a bare lowercase basename (vendor fields carry full paths)
_BASENAME = ("process.name", "process.parent", "target.process")
# Fields normalized to lowercase so rules need no (?i) gymnastics on values
_LOWER = ("file.path", "registry.key", "registry.value", "access_mask", "url.path",
          "dns.question.name", "destination.domain", "process.command_line")
# Extra fields the normalizer may add; kept so downstream indexing never KeyErrors
EXTRA_FIELDS = ["file.name", "process.image_raw", "source.ip_not_private",
                "destination.ip_not_private", "file.new_contents", "logon.failure",
                "logon.success", "web_auth_failure"]

AUTH_OUTCOME_BY_ID = {4624: "success", 4625: "failure", 4768: "failure", 4771: "failure",
                      4648: "success", 4672: "success", 1102: "success", 4720: "success",
                      4732: "success", 4688: "success"}
# EventID -> canonical dataset, so the *vendor* (Sysmon) never leaks into a rule condition
DATASET_BY_ID = {1: "process_creation", 3: "network_connection", 10: "process_access",
                 11: "file_event", 13: "registry", 23: "file_event", 26: "file_event",
                 1102: "log_clearing", 4688: "process_creation"}


def _clean(v):
    """Vendor placeholders that actually mean 'no value'."""
    if isinstance(v, str) and v.strip() in ("", "-", "N/A", "n/a", "None", "null", "(null)"):
        return None
    return v


def _base(v):
    return str(v).replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].lower()


def _fill(ev, key, value):
    value = _clean(value)
    if value is not None and _clean(ev.get(key)) is None:
        ev[key] = value


# --------------------------------------------------------------------- per-format parsers
def _norm_ts(raw):
    d = parse_ts(raw)
    return iso(d) if d else raw


def parse_jsonl(lines, dataset=None):
    out = []
    for line in lines:
        line = line.strip().strip("\r")
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            out.append({"_parse_error": "bad json", "raw": line[:200]})
            continue
        if not isinstance(ev, dict):
            out.append({"_parse_error": "json not an object", "raw": line[:200]})
            continue
        if dataset and not ev.get("event.dataset"):
            ev["event.dataset"] = dataset
        if ev.get("@timestamp"):
            ev["@timestamp"] = _norm_ts(ev["@timestamp"])
        out.append(ev)
    return out


def parse_apache(lines, dataset="web"):
    out = []
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        m = APACHE_RE.match(line)
        if not m:
            out.append({"_parse_error": "apache regex miss", "raw": line[:200]})
            continue
        g = m.groupdict()
        parts = (g.get("req") or "").split()
        method = parts[0] if parts else None
        path = parts[1] if len(parts) > 1 else None
        try:
            status = int(g["status"])
        except (TypeError, ValueError):
            status = None
        size = 0 if g["bytes"] in ("-", None) else int(g["bytes"])
        user = _clean(g["user"])
        out.append(ensure_schema({
            "@timestamp": _norm_ts(g["ts"]),
            "event.dataset": dataset,
            "event.action": "http-request",
            "event.outcome": "failure" if status and status >= 400 else "success",
            "source.ip": g["ip"],
            "http.request.method": method,
            "url.path": (path or "").lower(),
            "http.response.status_code": status,
            "network.bytes": size,
            "network.direction": "inbound",
            "user.name": user,
            "destination.domain": None,
            "tags": [f"ua:{(g.get('ua') or '-')[:64]}"],
            "event.original": line[:500],
        }))
    return out


def parse_syslog(lines, dataset="auth"):
    out = []
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        m = SYSLOG_RE.match(line)
        if not m:
            out.append({"_parse_error": "syslog regex miss", "raw": line[:200]})
            continue
        body = m.group("msg")
        kv = {}
        for mm in KV_RE.finditer(body):
            if mm.group(1):
                kv[mm.group(1)] = mm.group(2).replace('\\"', '"')
            else:
                kv[mm.group(3)] = mm.group(4)
        ev = ensure_schema({
            "@timestamp": _norm_ts(m.group("ts")),
            "event.dataset": dataset,
            "event.action": kv.pop("action", None) or "syslog-message",
            "event.outcome": kv.pop("outcome", None) or (
                "failure" if "Failed" in body else "success"),
            "source.ip": kv.pop("ip", None) or kv.pop("rport", None),
            "user.name": kv.pop("user", None),
            "host.name": m.group("host"),
            "process.name": (m.group("prog") or "").lower(),
            "event.original": line[:500],
            "tags": [f"prog:{m.group('prog')}"],
        })
        for k, v in kv.items():
            ev.setdefault(k, v)
        out.append(ev)
    return out


NUMERIC_FIELDS = {"source.port", "destination.port", "http.response.status_code",
                  "network.bytes", "file_count", "bytes_sent", "process.pid"}


def parse_delimited(lines, dataset=None, delimiter=",", aliases=None):
    aliases = aliases or {}
    text = "\n".join(l.rstrip("\r\n") for l in lines)
    out = []
    for row in csv.DictReader(io.StringIO(text), delimiter=delimiter):
        if row is None:
            continue
        if row.get(None):
            out.append({"_parse_error": "csv field count mismatch", "raw": str(row)[:200]})
            continue
        ev = {}
        for raw_key, v in row.items():
            if raw_key is None or v is None:
                continue
            field = aliases.get(raw_key.strip(), raw_key.strip())
            v = v.strip()
            if field == "@timestamp":
                v = _norm_ts(v)
            elif field in NUMERIC_FIELDS:
                try:
                    v = int(v)
                except ValueError:
                    try:
                        v = float(v)
                    except ValueError:
                        pass
            ev[field] = v
        ev.setdefault("event.dataset", dataset)
        ev.setdefault("event.action", "dns-query" if dataset == "dns" else "firewall-event")
        out.append(ensure_schema(ev))
    return out


FIREWALL_ALIASES = {k: v for k, v in ALIASES["Firewall"].items()}
FIREWALL_ALIASES.update({"ts": "@timestamp"})
DNS_ALIASES = dict(ALIASES["DNS"])
DNS_ALIASES.update({"ts": "@timestamp"})


# --------------------------------------------------------------------- normalization
def apply_aliases(ev, source_type):
    """Vendor fields -> schema fields, value normalization, derived flags and tags."""
    for raw, norm in ALIASES.get(source_type, {}).items():
        if raw in ev:
            _fill(ev, norm, _clean(ev[raw]))
    for f in _BASENAME:
        if isinstance(ev.get(f), str) and "\\" in str(ev[f]) + "/" or isinstance(ev.get(f), str):
            v = ev[f]
            if isinstance(v, str) and ("\\" in v or "/" in v):
                ev[f] = _base(v)
    for f in _LOWER:
        if isinstance(ev.get(f), str):
            ev[f] = ev[f].lower()

    for ipf, flag in (("source.ip", "source.ip_not_private"),
                      ("destination.ip", "destination.ip_not_private")):
        if ev.get(ipf):
            ev[flag] = not is_private(str(ev[ipf]))

    ds = (ev.get("event.dataset") or "").lower()
    tags = ev.setdefault("tags", [])
    if not isinstance(tags, list):
        ev["tags"] = tags = [str(tags)]

    eid = ev.get("EventID")
    try:
        eid = int(eid) if eid is not None else None
    except (TypeError, ValueError):
        eid = None
    if eid is not None:
        _fill(ev, "event.id", str(eid))
        if f"eventcode/{eid}" not in tags:
            tags.append(f"eventcode/{eid}")
        if ds == "authentication" and eid in AUTH_OUTCOME_BY_ID:
            outcome = AUTH_OUTCOME_BY_ID[eid]
            _fill(ev, "event.outcome", outcome)
            act = "successful-logon" if outcome == "success" else "failed-logon"
            _fill(ev, "event.action", act)
        if DATASET_BY_ID.get(eid) and ds in ("", "authentication", "sysmon_13", "file_create",
                                            "log_clearing", "process_access", "registry"):
            if eid != 1102:
                _fill(ev, "event.dataset", DATASET_BY_ID[eid])
        _fill(ev, "event.dataset", DATASET_BY_ID.get(eid))

    if eid == 1 or ds == "process_creation":
        img, pimg, cmd = ev.get("Image"), ev.get("ParentImage"), ev.get("CommandLine")
        if img:
            _fill(ev, "process.name", _base(img))
        if pimg:
            _fill(ev, "process.parent", _base(pimg))
        if cmd:
            _fill(ev, "process.command_line", cmd)
        _fill(ev, "event.action", "process-create")
        for tag in ("sysmon/1", "process-create"):
            if tag not in tags:
                tags.append(tag)
    if eid == 10 or ds == "process_access":
        if ev.get("Image") or ev.get("SourceImage"):
            _fill(ev, "process.name", _base(ev.get("SourceImage") or ev.get("Image")))
        if ev.get("TargetImage"):
            _fill(ev, "target.process", _base(ev["TargetImage"]))
        if ev.get("GrantedAccess"):
            _fill(ev, "access_mask", str(ev["GrantedAccess"]).lower())
        _fill(ev, "event.action", "process-access")
        for tag in ("sysmon/10", "process-access", "access-to-process"):
            if tag not in tags:
                tags.append(tag)
    if eid in (11, 23, 26) or ds == "file_event":
        if ev.get("TargetFilename"):
            _fill(ev, "file.path", str(ev["TargetFilename"]).lower())
            _fill(ev, "file.name", _base(ev["TargetFilename"]))
        _fill(ev, "event.action", "file-delete" if eid == 23 else "file-create")
        for tag in ("file-event", "file-create" if eid != 23 else "file-delete"):
            if tag not in tags:
                tags.append(tag)
    if eid == 13 or ds == "registry":
        if ev.get("TargetObject"):
            _fill(ev, "registry.key", str(ev["TargetObject"]).lower())
        if ev.get("Details"):
            _fill(ev, "registry.value", str(ev["Details"]).lower())
        _fill(ev, "event.action", "registry-set-value")
        for tag in ("sysmon/13", "registry-event", "registry-set-value"):
            if tag not in tags:
                tags.append(tag)
    if ev.get("ProcessCreate") and isinstance(ev["ProcessCreate"], dict):
        pc = ev["ProcessCreate"]
        _fill(ev, "process.name", _base(pc.get("Image", "")))
        _fill(ev, "process.parent", _base(pc.get("ParentImage", "")))
        _fill(ev, "process.command_line", pc.get("CommandLine"))
        if "process-create" not in tags:
            tags.append("process-create")

    if ds in ("web", "proxy") or source_type == "Apache":
        _fill(ev, "event.action", "http-request")
        if "web-request" not in tags:
            tags.append("web-request")
        if ev.get("http.response.status_code") in (401, 403):
            _fill(ev, "event.outcome", "failure")
        if ev.get("destination.domain"):
            ev["destination.domain"] = str(ev["destination.domain"]).lower()
        if ds == "proxy" or source_type == "Proxy":
            _fill(ev, "network.direction", "outbound")
        if "auth" in str(ev.get("url.path") or ""):
            _fill(ev, "web_auth_failure", True)
    if ds == "dns" or source_type == "DNS":
        _fill(ev, "event.action", "dns-query")
        _fill(ev, "event.dataset", "dns")
        _fill(ev, "network.direction", "outbound")
        if ev.get("dns.rcode") and "NXDOMAIN" in str(ev["dns.rcode"]).upper():
            if "nxdomain" not in tags:
                tags.append("nxdomain")
    if ds == "firewall" or source_type == "Firewall":
        _fill(ev, "event.dataset", "firewall")
        if ev.get("event.action"):
            ev["event.action"] = str(ev["event.action"]).lower()
        _fill(ev, "network.direction", "outbound")
    if ds == "auth" or source_type == "SSH":
        _fill(ev, "event.dataset", "auth")
        outcome = _clean(ev.get("event.outcome"))
        if outcome:
            outcome = str(outcome).lower()
            ev["event.outcome"] = outcome
            _fill(ev, "event.action", "authentication-failure" if outcome == "failure"
                  else "authentication-success")
    if ev.get("event.action") in ("failed-logon", "authentication-failure"):
        ev["logon.failure"] = True
    if ev.get("event.action") in ("successful-logon", "authentication-success"):
        ev["logon.success"] = True
    for f in EXTRA_FIELDS + FIELDS:
        ev.setdefault(f, None)
    return ev


# --------------------------------------------------------------------- driver
def read_source(path, spec):
    """Read one raw file per its config spec -> (normalized events, stats dict)."""
    import pathlib
    path = path if isinstance(path, pathlib.Path) else pathlib.Path(str(path))
    stype, dataset = spec.get("type", "jsonl"), spec.get("dataset")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    if stype == "apache":
        events = parse_apache(lines, dataset=dataset or "web")
    elif stype == "syslog":
        events = parse_syslog(lines, dataset=dataset or "auth")
    elif stype == "csv":
        if dataset == "dns":
            aliases = DNS_ALIASES
        elif dataset == "firewall":
            aliases = FIREWALL_ALIASES
        else:
            aliases = spec.get("aliases") or {}
        events = parse_delimited(lines, dataset=dataset,
                                 delimiter=spec.get("delimiter", ","), aliases=aliases)
    else:
        events = parse_jsonl(lines, dataset=dataset)
    good, bad = [], 0
    for ev in events:
        if "_parse_error" in ev:
            bad += 1
            continue
        ev = ensure_schema(ev)
        if parse_ts(ev.get("@timestamp")) is None:
            bad += 1
            continue
        apply_aliases(ev, spec.get("source_type"))
        good.append(ev)
    return good, {"lines": len(lines), "parsed": len(good), "parse_errors": bad}
