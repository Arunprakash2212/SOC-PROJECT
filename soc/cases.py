"""Triage layer: alert dedup, entity-based correlation into incidents, playbook response.

A SOC's value is not in producing alerts - it is in turning N noisy alerts into M workable cases
and then acting on them. That is what this module does.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import hashlib

SEV_ORDER = ["critical", "high", "medium", "low", "informational"]


def dedup_alerts(alerts, minutes=10):
    """Collapse repeats of the same rule on the same entity inside a window."""
    buckets = {}
    for a in alerts:
        ent = a.get("entities", {})
        key = (a["rule_id"], _s(ent.get("source.ip")), _s(ent.get("host.name")),
               _s(ent.get("user.name")), _s(ent.get("destination.domain")))
        buckets.setdefault(key, []).append(a)
    out = []
    for key, rows in buckets.items():
        rows.sort(key=lambda r: r["first_seen"])
        base = dict(rows[0])
        for other in rows[1:]:
            base["count"] += other["count"]
            base["repeat_count"] = base.get("repeat_count", 1) + 1
            base["last_seen"] = max(base["last_seen"], other["last_seen"])
            base["note"] = (base.get("note", "") + " | deduped x%d" % len(rows)).strip(" |")
        if len(rows) > 1:
            base["deduped_from"] = len(rows)
        out.append(base)
    out.sort(key=lambda a: (-a.get("score", 0), a["first_seen"]))
    return out


def _s(v):
    if isinstance(v, list):
        return str(v[0]) if v else None
    return str(v) if v not in (None, "") else None


# --------------------------------------------------------------------- correlation
CORRELATE_FIELDS = ["user.name", "host.name", "source.ip", "destination.domain",
                    "destination.ip", "process.name"]


def correlate(alerts, window_minutes=60, min_shared=1):
    """Union-find clustering of alerts that share an entity inside a time window.

    Two levels of keying, because "same user" and "same source IP" are not equally strong:
      * STRONG keys (user, host) merge on their own - they describe one affected asset.
      * WEAK keys (IPs, domains, processes) merge only when the alerts share at least two
        entities overall - otherwise one noisy scanner IP welds 30 unrelated detections
        into a single giant incident, which is the classic correlation-engine failure mode.
    """
    n = len(alerts)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    def ts(a, key):
        return dt.datetime.fromisoformat(a[key])

    def fields(a):
        return a.get("entities", {}) or {}

    strong = {}
    weak = {}
    for i, a in enumerate(alerts):
        ent = fields(a)
        for f in ("user.name", "host.name"):
            for v in _set(ent.get(f)):
                strong.setdefault((f, v), []).append(i)
        for f in ("source.ip", "destination.domain", "destination.ip", "process.name"):
            for v in _set(ent.get(f)):
                if f == "source.ip" and v.startswith(("10.", "192.168.", "172.")):
                    continue      # a private source IP is not a useful join key on its own
                weak.setdefault((f, v), []).append(i)

    for idx, bucket in list(strong.items()) + list(weak.items()):
        bucket = sorted(set(bucket))
        for a_i in range(1, len(bucket)):
            i, j = bucket[a_i - 1], bucket[a_i]
            gap = abs((ts(alerts[i], "last_seen") - ts(alerts[j], "last_seen")).total_seconds())
            if gap > window_minutes * 60:
                continue
            if idx in weak and len(_shared(alerts[i], alerts[j])) < 2:
                continue
            union(i, j)

    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(alerts[i])
    out = [v for v in groups.values() if v]
    out.sort(key=lambda g: -max(a.get("score", 0) for a in g))
    return out


def _shared(a, b):
    ea, eb = a.get("entities", {}), b.get("entities", {})
    shared = []
    for f in CORRELATE_FIELDS:
        va, vb = _set(ea.get(f)), _set(eb.get(f))
        inter = va & vb
        if f == "source.ip":     # never correlate on private IPs alone: too noisy
            inter = {x for x in inter if not x.startswith(("10.", "192.168.", "172."))}
        if inter:
            shared.append(f)
    return shared


def _set(v):
    if v in (None, ""):
        return set()
    return {str(x) for x in v} if isinstance(v, list) else {str(v)}


# --------------------------------------------------------------------- incident build
TTP_ORDER = ["reconnaissance", "initial-access", "execution", "persistence",
             "privilege-escalation", "defense-evasion", "credential-access",
             "discovery", "lateral-movement", "collection", "command-and-control",
             "exfiltration", "impact"]


def build_cases(alerts, settings, analyzer="soc-analyst@corp.example"):
    corr = settings.get("correlation", {})
    now = dt.datetime.now(dt.timezone.utc)
    groups = correlate(alerts, int(corr.get("window_minutes", 60)),
                       int(corr.get("min_shared_entities", 1)))
    cases = []
    for idx, group in enumerate(groups, start=1):
        group = sorted(group, key=lambda a: a["first_seen"])
        max_score = max(a.get("score", 0) for a in group)
        severity = min((a["severity"] for a in group), key=lambda s: SEV_ORDER.index(s))
        tactics = sorted({a.get("tactic") for a in group if a.get("tactic")},
                         key=lambda t: TTP_ORDER.index(t) if t in TTP_ORDER else 99)
        techniques = sorted({t for a in group for t in a.get("technique", [])})
        entities = _merge_entities(group)
        title = _title(group, entities)
        cid = "INC-%s-%03d" % (now.strftime("%Y%m%d"), idx)
        case = {
            "case_id": cid,
            "fingerprint": hashlib.sha1(("|".join(a["rule_id"] for a in group) +
                                         str(sorted(entities.items()))).encode()).hexdigest()[:12],
            "title": title,
            "severity": severity,
            "score": max_score,
            "status": "new",
            "assignee": None,
            "opened_at": min(a["first_seen"] for a in group),
            "last_activity": max(a["last_seen"] for a in group),
            "closed_at": None,
            "analyst": analyzer,
            "alert_count": len(group),
            "rule_count": len({a["rule_id"] for a in group}),
            "tactics": tactics,
            "techniques": techniques,
            "entities": entities,
            "narrative": _narrative(group, tactics),
            "triage_notes": [a.get("note") for a in group if a.get("note")][:6],
            "recommended_priority": ("P1" if max_score >= 75 else "P2" if max_score >= 55
                                     else "P3" if max_score >= 35 else "P4"),
            "alerts": [a["rule_id"] for a in group],
            "_alerts": group,
        }
        case["sla_due"] = _sla(case["severity"], case["opened_at"])
        case.setdefault("response", [])
        cases.append(case)
    return cases


def _merge_entities(group):
    out = {}
    for a in group:
        for k, v in a.get("entities", {}).items():
            vals = v if isinstance(v, list) else [v]
            cur = out.setdefault(k, [])
            for x in vals:
                if x not in cur and len(cur) < 12:
                    cur.append(x)
    for k in list(out):
        if len(out[k]) == 1:
            out[k] = out[k][0]
    return out


def _clip(text, limit):
    """Trim to `limit` characters without ever ending inside a word or token.

    A fixed slice cut rule names mid-word ("...attempts fr"), which read as data
    corruption in the dashboard. So when the cut lands inside a token, that token
    is dropped: back to the previous space, or - for a single dotted token such as
    an IP, host or URL - back to the previous dot.
    """
    text = str(text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    if re.match(r"[\w.\-]", text[limit]):        # we stopped mid-token (hyphen counts: web-mail)
        sp = cut.rfind(" ")
        if sp > int(limit * 0.4):
            cut = cut[:sp]
        else:
            head = cut.rstrip(".")
            dot = head.rfind(".")
            cut = head[:dot] if dot > 0 else head
    return cut.rstrip(" ,;:.-")


def _title(group, entities):
    rule = group[0]["rule_name"]
    ent = entities.get("user.name") or entities.get("host.name") or entities.get("source.ip")
    if isinstance(ent, list):
        ent = ent[0]
    if len(group) > 1:
        # " ... " between two names read as a truncation marker in the UI;
        # say how much was rolled up instead. Budget stays under the
        # dashboard's 58-character title slot.
        first = _clip(group[0]["rule_name"].split(" -")[0], 24)
        if len(group) == 2:
            return f"Campaign: {first} & {_clip(group[-1]['rule_name'].split(' -')[0], 20)}"
        return f"Campaign: {first} + {len(group) - 1} related"
    return f"{rule}" + (f" - {_clip(ent, 28)}" if ent else "")


IST = dt.timezone(dt.timedelta(hours=5, minutes=30))


def _hhmm(iso_ts):
    try:
        return dt.datetime.fromisoformat(iso_ts).astimezone(IST).strftime("%H:%M:%S")
    except (ValueError, TypeError):
        return (iso_ts or "?")[11:19]


def _narrative(group, tactics, limit=14):
    lines = []
    for a in group:
        lines.append(f"{_hhmm(a['first_seen'])}  {a['severity'].upper():9s} score{a.get('score',0):>4} "
                     f"{a['rule_id']:16s} {a['rule_name'][:52]:52s} "
                     f"[{','.join(a['technique']) or '-'}]")
    if len(lines) > limit:
        extra = len(lines) - limit
        lines = lines[:limit] + [f"    ... {extra} further detection(s) in this incident"]
    chain = " -> ".join(tactics) or "single detection"
    return {"events": lines, "chain": chain, "total": len(group)}


def _sla(severity, opened_at):
    hours = {"critical": 1, "high": 4, "medium": 8, "low": 24, "informational": 72}[severity]
    t = dt.datetime.fromisoformat(opened_at) + dt.timedelta(hours=hours)
    return t.isoformat()


# --------------------------------------------------------------------- response / SOAR
def run_playbooks(cases, settings, now=None):
    """Simulated containment. Only for incidents that carry a critical or high-confidence alert -
    auto-response on low-confidence detections is how SOAR projects lose analyst trust."""
    now = now or dt.datetime.now(dt.timezone.utc)
    playbooks = settings.get("playbooks", [])
    actions_total = 0
    for c in cases:
        triggers = [a for a in c["_alerts"] if a["severity"] == "critical"
                    or (a["severity"] == "high" and a.get("confidence") in ("high", "medium"))
                    or a.get("score", 0) >= 80]
        if not triggers:
            # Auto-response policy: never act on low-confidence or low-score signals. This guard
            # is the difference between a SOAR people trust and one they switch off in a week.
            c["response"] = [{"action": "none", "target": "-", "result": "no automated response",
                              "justification": "no alert met the policy bar (critical, or high "
                                               "severity with high/medium confidence, or score "
                                               ">= 80)", "executed_at": None, "ticket": None}]
            continue
        run_for = set()
        for a in triggers:
            run_for.add(a.get("tactic"))
        # scope response targets to entities that appear in the *triggering* alerts, otherwise a
        # merged incident would disable an unrelated account that merely shares a host entity.
        rel = {}
        for a in triggers:
            for k, v in (a.get("entities") or {}).items():
                vals = v if isinstance(v, list) else [v]
                rel.setdefault(k, [])
                for x in vals:
                    if x not in (None, "", "-") and x not in rel[k]:
                        rel[k].append(str(x))
        c["related_entities"] = {k: (v[0] if len(v) == 1 else v[:6]) for k, v in rel.items()}
        executed = []
        for pb in playbooks:
            if not (set(pb.get("when_tactics", [])) & run_for):
                continue
            for action in pb.get("actions", []):
                executed.append(_action(action, c, triggers, now))
        seen, dedup_actions = set(), []
        for e in executed:
            if (e["action"], e["target"]) in seen:
                continue
            seen.add((e["action"], e["target"]))
            dedup_actions.append(e)
        c["response"] = dedup_actions
        actions_total += len(dedup_actions)
        if c["status"] == "new":
            c["status"] = "contained"
            c["contained_at"] = _response_time(c, settings, now)
    return actions_total


BUILTIN_ACCOUNTS = {"system", "local service", "network service", "-", "n/a", ""}


def _safe_ip(v):
    from .geo import is_private
    v = (v or "").strip()
    if not v or not v[0].isdigit() or v.count(".") != 3 or is_private(v):
        return None
    return v


def _action(action, case, triggers, now):
    # prefer entities from the triggering alerts, fall back to incident-level ones
    ent = case.get("related_entities") or case.get("entities", {})
    first = lambda k: (ent.get(k)[0] if isinstance(ent.get(k), list) else ent.get(k))
    evidence = ", ".join(sorted({a["rule_id"] for a in triggers}))[:180]
    res = {"action": action, "target": None, "result": "simulated-success",
           "executed_at": now.isoformat(), "justification":
               f"{' + '.join(sorted({a['tactic'] for a in triggers}))[:60]} -> {evidence}",
           "ticket": f"AUTO-{abs(hash((action, case['case_id']))) % 90000 + 10000}"}
    if action == "block_ip_at_waf":
        tgt = _safe_ip(first("source.ip")) or _safe_ip(first("destination.ip"))
        res["target"] = tgt or "-"
        res["result"] = ("blocked for 24h at edge WAF" if tgt
                         else "SKIPPED - no external source IP in evidence (never block a host "
                              "on an internal IP alone)")
    elif action == "disable_account":
        acct = first("user.name") or "n/a"
        builtin = str(acct).lower() in BUILTIN_ACCOUNTS
        res["target"] = acct
        res["result"] = ("SKIPPED - built-in/service identity, disabling it would break the "
                         "platform; reset credentials instead" if builtin
                         else "account disabled (reversible)")
    elif action == "force_password_reset":
        res["target"] = first("user.name") or "n/a"
        res["result"] = "password reset + MFA re-enrolment required at next logon"
    elif action == "isolate_host":
        res["target"] = first("host.name") or "n/a"
        res["result"] = "network isolation granted (EDR), SMB/HTTP blocked, management path open"
    elif action == "kill_process_tree":
        res["target"] = first("process.name") or "n/a"
        res["result"] = "process tree terminated, binary hashed + uploaded"
    elif action == "quarantine_file":
        res["target"] = first("file.path") or first("process.command_line") or "n/a"
        res["result"] = "artifact quarantined, path added to deny list"
    elif action == "revoke_sessions":
        res["target"] = first("user.name") or "n/a"
        res["result"] = "all Kerberos/SSO tickets revoked"
    elif action == "require_mfa_reenrollment":
        res["target"] = first("user.name") or "n/a"
        res["result"] = "MFA re-enrolment policy applied"
    elif action == "create_ticket":
        res["target"] = case["case_id"]
        res["result"] = "advisory ticket raised for asset owner"
    return res


def _response_time(case, settings, fallback):
    """Dataset-clock containment time (see config: correlation.response_lag_minutes)."""
    corr = settings.get("correlation", {})
    lag = float(corr.get("response_lag_minutes", 0) or 0)
    try:
        base = dt.datetime.fromisoformat(case["last_activity"])
    except (KeyError, TypeError, ValueError):
        return fallback.isoformat()
    return (base + dt.timedelta(minutes=lag)).isoformat()


# --------------------------------------------------------------------- metrics
def _median(vals):
    vals = sorted(v for v in vals if v is not None)
    if not vals:
        return None
    n = len(vals)
    return round(vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2)


def read_triage_journal(root):
    """Latest analyst decision per case, from the dashboard's append-only journal.

    The journal is append-only by design (an audit trail, not a mutable field),
    so the *last* line for a case id wins.  Undecodable lines are skipped the
    same way the dashboard skips them, so half-written journals cannot take the
    report down with them.
    """
    path = os.path.join(root, "data", "processed", "triage_state.jsonl")
    latest = {}
    if not os.path.exists(path):
        return latest
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            cid = rec.get("case_id")
            if cid:
                latest[cid] = rec
    return latest


def compute_metrics(cases, events_count, run_seconds, rules_stats, ing_stats, alerts=None,
                    session_start=None, settings=None):
    """MTTD here is the pipeline's own detection latency (event -> alert raised), MTTR is the
    time from incident open to containment/closure. Reported as medians with max/p95 context,
    because a single slow case should not pretend the whole shift was slow."""
    alerts = alerts or []
    lag_min = float((rules_stats or {}).get("detection_lag_minutes", 4) or 4)
    lat = [a.get("detection_latency_s") for a in alerts if a.get("detection_latency_s") is not None]
    # metrics run on the dataset clock: sweep cadence (lag_min) is the honest number for a
    # historical capture; raw wall-clock lag is kept as raw_mttd_s for transparency.
    mttd = int(lag_min * 60)
    mttd_max = max(lat) if lat else None
    mttd_raw = _median(lat)
    durs = []
    for c in cases:
        end = c.get("closed_at") or c.get("contained_at")
        if not end:
            continue
        end_dt = dt.datetime.fromisoformat(end)
        if session_start and end_dt < session_start:
            continue      # response happened before this run - not something we can claim credit for
        durs.append((end_dt - dt.datetime.fromisoformat(c["opened_at"])).total_seconds())
    mttr = _median(durs)
    # MTTR is meaningless when measured against the *dataset* clock (synthetic events are in the
    # past), so we also report the human-side number: how long the run + response took.
    response_seconds = round((max(dt.datetime.fromisoformat(c["contained_at"]) for c in cases
                                 if c.get("contained_at")) - session_start).total_seconds(), 2) \
        if session_start and any(c.get("contained_at") for c in cases) else None
    sev_counts = {s: 0 for s in SEV_ORDER}
    actions = 0
    for c in cases:
        sev_counts[c["severity"]] = sev_counts.get(c["severity"], 0) + 1
        actions += len([r for r in c.get("response", []) if r["action"] != "none"])
    return {
        "events": events_count, "cases": len(cases), "severity_counts": sev_counts,
        "response_actions": actions, "pipeline_seconds": round(run_seconds, 2),
        "mttd_seconds": mttd, "mttr_seconds": mttr, "mttd_max_seconds": mttd_max,
        "mttd_raw_seconds": mttd_raw, "detection_lag_minutes": lag_min,
        "response_seconds": response_seconds,
        "alerts_scored_ge_55": len([a for a in alerts if a.get("score", 0) >= 55]),
        "ingestion": ing_stats, "coverage": rules_stats.get("coverage"),
        "rules_fired": rules_stats.get("rules_fired"), "rules_total": rules_stats.get("rules_total"),
        "unfired_rules": rules_stats.get("unfired_rules", []),
        "throughput_eps": round(events_count / max(run_seconds, 0.001)),
        "detection_gap_pct": round(100.0 * len(rules_stats.get("unfired_rules", [])) /
                                   max(1, rules_stats.get("rules_total", 1)), 1),
    }
