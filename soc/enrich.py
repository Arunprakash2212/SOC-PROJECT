"""Enrichment + alert scoring: turn a raw detection into something triage can act on."""
from __future__ import annotations

import yaml

from .geo import is_private, locate

PRIVILEGED_HINTS = ("admin", "root", "svc-", "system", "sa", "backup", "operator", ".adm")


class Intel:
    """Static offline threat-intel feed + entity risk attributes."""

    def __init__(self, intel_path=None, users=None, hosts=None):
        self.ip, self.domain = {}, {}
        if intel_path:
            with open(intel_path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            self.ip = data.get("ip", {}) or {}
            self.domain = data.get("domain", {}) or {}
        self.users = users or {}
        self.hosts = hosts or {}

    def lookup_ip(self, ip):
        if not ip:
            return None
        hit = self.ip.get(str(ip).strip())
        if hit:
            return {"type": "ip", "value": ip, **hit}
        loc = locate(ip) or {}
        if loc.get("category") == "anonymizer":
            return {"type": "ip", "value": ip, "category": "anonymizer",
                    "source": "static-anonymizer-list", "confidence": 60,
                    "note": loc.get("label")}
        return None

    def lookup_domain(self, dom):
        if not dom:
            return None
        for suffix, meta in self.domain.items():
            if str(dom).lower().endswith(suffix.lower()):
                return {"type": "domain", "value": dom, **meta}
        return None


def user_attributes(name):
    n = (name or "").lower()
    privileged = any(h in n for h in PRIVILEGED_HINTS)
    failed = 0
    risk = 10 + (25 if privileged else 0) + min(40, failed * 5)
    return {"name": name, "privileged": privileged, "risk_score": min(100, risk),
            "mfa_enrolled": not (name or "").lower().startswith("svc-"),
            "manager": "it-secops@corp.example"}


def host_attributes(name):
    n = (name or "").upper()
    if n.startswith(("SRV", "DC-", "LINUX-PROD")):
        return {"name": name, "criticality": "high", "os": "Windows Server 2022",
                "agent": "EDR online", "exposure": "server-vlan"}
    if n.startswith(("WS-", "LAPTOP")):
        return {"name": name, "criticality": "medium", "os": "Windows 11",
                "agent": "EDR online", "exposure": "user-vlan"}
    return {"name": name, "criticality": "unknown", "os": "unknown", "agent": "unknown",
            "exposure": "unknown"}


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# Asset inventory: workstation IPs -> host names (in a real SOC this is the CMDB/EDR API).
ASSET_DB = {
    "10.10.31.27": "WS-FINANCE-07", "10.10.31.44": "WS-HR-03", "10.10.31.58": "WS-ENG-12",
    "10.10.31.61": "WS-MKT-02", "10.10.31.73": "WS-OPS-09", "10.10.20.11": "SRV-BKP-01",
    "10.10.10.5": "DC-01", "10.10.20.30": "SRV-WEB-01", "10.10.20.40": "SRV-FILE-01",
}

PRIVILEGED_HINTS2 = PRIVILEGED_HINTS


def resolve_hosts(alerts):
    """Fill host.name from the asset inventory when a log source did not carry it."""
    for a in alerts:
        ent = a.setdefault("entities", {})
        if not ent.get("host.name"):
            ips = ent.get("source.ip") or ent.get("destination.ip")
            ips = ips if isinstance(ips, list) else [ips]
            got = [ASSET_DB[i] for i in ips if i in ASSET_DB]
            if got:
                ent["host.name"] = got[0] if len(got) == 1 else got[:6]
    return alerts


def enrich_alerts(alerts, settings, intel):
    """Add entities, intel hits, a score and a triage summary to each alert (in place)."""
    sc = settings.get("scoring", {})
    weights = sc.get("severity_weight", {})
    boosts = sc.get("boosts", {})
    cap = sc.get("cap", 100)
    resolve_hosts(alerts)
    for a in alerts:
        ent = a.setdefault("entities", {})
        reasons, score = [], float(weights.get(a.get("severity"), 20))
        score += float(a.get("risk", 0)) * 0.15
        reasons.append(f"rule severity {a.get('severity')} + rule risk {a.get('risk')}")

        src_ips = ent.get("source.ip") if isinstance(ent.get("source.ip"), list) else \
            [ent.get("source.ip")] if ent.get("source.ip") else []
        ext = [i for i in src_ips if i and not is_private(i)]
        if ext:
            score += boosts.get("ip_in_threat_intel", 0) * 0.4
            reasons.append(f"external source {ext[0]} ({(locate(ext[0]) or {}).get('label')})")
        hits = []
        for ip in src_ips + [ent.get("destination.ip")]:
            h = intel.lookup_ip(ip)
            if h:
                hits.append(h)
        for d in ([ent.get("destination.domain")] if ent.get("destination.domain") else []) + \
                 (ent.get("dns.question.name") if isinstance(ent.get("dns.question.name"), list)
                  else [ent.get("dns.question.name")]):
            h = intel.lookup_domain(d)
            if h:
                hits.append(h)
        hits = [h for h in hits if h]
        if hits:
            score += boosts.get("ip_in_threat_intel", 0) + max(0, (max(
                int(h.get("confidence", 0)) for h in hits) - 60) / 2)
            reasons.append("threat intel: " + ", ".join(
                f"{h['value']}={h['category']}(conf {h.get('confidence')})" for h in hits[:4]))

        user = ent.get("user.name")
        if isinstance(user, list):
            user = user[0]
        ua = user_attributes(user)
        if ua["privileged"]:
            score += boosts.get("user_is_privileged", 0)
            reasons.append(f"privileged service account ({user})")
        if user and not ua["mfa_enrolled"]:
            score += boosts.get("user_risk_high", 0)
            reasons.append("MFA not enrolled")

        host = ent.get("host.name")
        if isinstance(host, list):
            host = host[0]
        ha = host_attributes(host)
        if ha["criticality"] == "high":
            score += boosts.get("host_is_critical", 0)
            reasons.append(f"high-criticality asset ({host})")

        n_ent = len({k for k in ent if ent.get(k)})
        if n_ent >= 5:
            score += boosts.get("multiple_entities", 0)
            reasons.append(f"{n_ent} distinct entity types")

        mx = max([_num(x) or 0 for x in _flatten(ent.get("network.bytes"))] +
                 [_num(x) or 0 for x in _flatten(ent.get("bytes_sent"))] or [0])
        if mx and mx >= 100_000_000:
            score += boosts.get("exfil_bytes_gt_100mb", 0)
            reasons.append(f"largest single transfer {mx/1e6:.0f} MB")

        if a.get("baseline", {}).get("cov") is not None:
            score += 6
            reasons.append(f"beaconing CoV {a['baseline']['cov']}")
        if a.get("prior_events"):
            score += boosts.get("payload_executed", 0)
            reasons.append(f"sequence hit ({a['prior_events']} prior events)")

        a["score"] = round(min(cap, score))
        a["score_reasons"] = reasons
        a["enrichment"] = {"intel": hits, "user": ua, "host": ha,
                           "source_geo": [locate(i) for i in src_ips if i],
                           "dest_geo": [locate(ent.get("destination.ip"))]
                           if ent.get("destination.ip") else []}
        a["triage_suggested"] = ("escalate" if a["score"] >= 75 else
                                 "investigate" if a["score"] >= 55 else
                                 "monitor" if a["score"] >= 35 else "close-fp")
        a.setdefault("repeat_count", 1)
    alerts.sort(key=lambda x: (-x["score"], x["first_seen"]))
    return alerts


def _flatten(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]
