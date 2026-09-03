"""Detection engine: Sigma-style YAML rules evaluated over the normalized event stream.

Why hand-rolled instead of a SIEM? Because the point of the exercise is to show *how* a SOC
detects things: predicate matching on a normalized schema, deny-lists for false positives,
rate/distinct thresholds for behavioural rules, sequence dependencies to raise confidence, and
a statistical baseline (beaconing CoV) that works with no IOC at all.

Supported rule keys
-------------------
logsource.dataset   list of event.dataset values to scan (empty -> all events)
condition           list of groups; a group is a dict of AND'ed matchers; groups are OR'ed
filter              same shape as condition - any hit drops the match (false-positive control)
threshold           {field, distinct_field, min_events, window_minutes}
requires            {condition, min_count, window_minutes, key_fields} - prior-event dependency
window              {group_by, span_minutes, geo_field, min_distance_km} - grouped stats
config              {group_by, threshold, time_stats, exclude_processes} - baseline/anomaly
"""
from __future__ import annotations

import datetime as dt
import glob
import math
import os
import re

import yaml

from .event_schema import event_ts

TRUE_VALS = ("true", "yes", "1")


# --------------------------------------------------------------------------- predicates
def _as_list(v):
    return v if isinstance(v, list) else [v]


def _match_clause(field: str, spec, ev: dict) -> bool:
    if field == "@any_of":
        return any(match_group(g, ev) for g in _as_list(spec))
    if field == "@all":
        return all(match_group(g, ev) for g in _as_list(spec))
    if field == "tags":
        tags = ev.get("tags") or []
        return any(t in tags for t in _as_list(spec))
    if field.endswith(":exists"):
        return ev.get(field[:-len(":exists")]) not in (None, "", [])
    val = ev.get(field)
    if isinstance(spec, dict):
        for op, operand in spec.items():
            if op == "exists":
                want = str(operand).lower() in TRUE_VALS
                got = val not in (None, "", [])
                if got != want:
                    return False
            elif op == "regex":
                if val is None or not re.search(operand, str(val)):
                    return False
            elif op == "wildcard":
                pats = [p.lower() for p in _as_list(operand)]
                if val is None:
                    return False
                v = str(val).lower()
                if not any(re.match("^" + re.escape(p).replace("\\*", ".*") + "$", v) for p in pats):
                    return False
            elif op == "cidr":
                if val is None or not _in_any_cidr(str(val), _as_list(operand)):
                    return False
            elif op == "all":           # val is a list that must contain all operands
                if not isinstance(val, list) or not all(o in val for o in _as_list(operand)):
                    return False
            elif op in ("gt", "gte", "lt", "lte"):
                try:
                    f, o = float(val), float(operand)
                except (TypeError, ValueError):
                    return False
                if not {"gt": f > o, "gte": f >= o, "lt": f < o, "lte": f <= o}[op]:
                    return False
            elif op == "equals":
                if str(val).lower() != str(operand).lower():
                    return False
            else:
                raise ValueError(f"unknown operator {op!r}")
        return True
    if val is None:
        return False
    if isinstance(spec, bool):
        return bool(val) is spec
    if isinstance(val, list):
        # list-valued event field: match if ANY element equals, or CONTAINS, the spec
        return any(_eq(v, spec) for v in val)
    return _eq(val, spec)


def _eq(value, spec) -> bool:
    """Scalar/list membership semantics: spec may be a list (any of) or a single value."""
    sv = str(value).lower()
    if isinstance(spec, (list, tuple, set)):
        return any(sv == str(x).lower() for x in spec)
    return sv == str(spec).lower()


def match_group(group: dict, ev: dict) -> bool:
    if not isinstance(group, dict):
        return False
    return all(_match_clause(str(k), v, ev) for k, v in group.items())


def _in_any_cidr(ip: str, cidrs) -> bool:
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------- rule model
class Rule:
    def __init__(self, doc: dict, source: str = "<inline>"):
        self.raw = doc
        self.source = source
        self.id = doc.get("id") or doc.get("title") or "UNNAMED"
        self.name = doc.get("name") or self.id
        self.description = (doc.get("description") or "").strip()
        self.severity = doc.get("severity", "medium")
        self.confidence = doc.get("confidence", "medium")
        self.risk = int(doc.get("risk", 40))
        self.tactic = doc.get("tactic", "unknown")
        self.category = doc.get("category", "general")
        self.technique = _as_list(doc.get("technique", []))
        self.references = _as_list(doc.get("references", []))
        self.datasets = set(_as_list((doc.get("logsource") or {}).get("dataset", [])))
        self.conditions = doc.get("condition") or []
        if isinstance(self.conditions, dict):
            self.conditions = [self.conditions]
        self.filters = doc.get("filter") or []
        if isinstance(self.filters, dict):
            self.filters = [self.filters]
        self.threshold = doc.get("threshold") or {}
        self.requires = doc.get("requires") or {}
        self.window = doc.get("window") or {}
        self.cfg = doc.get("config") or {}
        self.enabled = doc.get("enabled", True)

    # -- event level -------------------------------------------------------
    def primary_hit(self, ev) -> bool:
        return any(match_group(g, ev) for g in self.conditions)

    def is_filtered(self, ev) -> bool:
        return any(match_group(g, ev) for g in self.filters)

    def secondary_hit(self, ev) -> bool:
        cond = self.requires.get("condition") or []
        if isinstance(cond, dict):
            cond = [cond]
        return any(match_group(g, ev) for g in cond)

    def applies(self, ev) -> bool:
        if not self.datasets:
            return True
        return (ev.get("event.dataset") or "") in self.datasets

    def __repr__(self):
        return f"<Rule {self.id} ({self.severity})>"


def _is_template(name: str) -> bool:
    """Template/sample files live in rules/ for convenience and must never be loaded.

    Matching on "_" alone is not enough: an underscore-led filename is exactly the thing that
    gets eaten when a file is copied out of a chat window, a wiki or a zip on some filesystems,
    and a broken template then stops the whole pipeline for no reason.
    """
    low = name.lower()
    return low.startswith("_") or "template" in low or low.startswith("sample")


def load_rules(rules_dir) -> list:
    """Load and validate rules/*.yaml.

    Two failure modes get special treatment, because both waste hours and neither message is
    obvious from the raw traceback:

    * duplicate rule ids - one file is shadowing another (usually an older draft left behind).
    * a YAML syntax error - reported with the file, line, column, the offending text and the
      single most common cause (a block scalar `>-` inside a flow mapping `{...}`).

    Every broken file is reported at once, so you fix the directory in one pass instead of
    re-running to discover the next failure.
    """
    rules, owner, broken, dups = [], {}, [], []
    for path in sorted(glob.glob(os.path.join(str(rules_dir), "*.yaml"))):
        name = os.path.basename(path)
        if _is_template(name):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                docs = yaml.safe_load(fh) or []
        except yaml.YAMLError as exc:
            line = col = None
            mark = getattr(exc, "problem_mark", None)
            if mark is not None:
                line, col = mark.line + 1, mark.column + 1
            snippet = ""
            try:
                with open(path, encoding="utf-8") as fh:
                    src = fh.read().splitlines()
                if line and 0 < line <= len(src):
                    snippet = src[line - 1].strip()
            except OSError:
                pass
            broken.append((name, line, col, str(exc.problem or exc).strip().splitlines()[0],
                            snippet))
            continue
        if isinstance(docs, dict):
            docs = [docs]
        if not isinstance(docs, list):
            broken.append((name, None, None, "top level must be a list of rules (or one rule)",
                           ""))
            docs = []
        for idx, doc in enumerate(docs, 1):
            if not isinstance(doc, dict):
                broken.append((name, None, None,
                               f"entry {idx} is not a mapping "
                               f"(got {type(doc).__name__})", str(doc)[:90]))
                continue
            r = Rule(doc, name)
            if r.id in owner:
                dups.append(f"duplicate rule id {r.id!r} - declared in both "
                            f"{os.path.basename(owner[r.id])} and {name}")
                continue
            owner[r.id] = path
            if r.enabled:
                rules.append(r)
    if broken or dups:
        lines = ["[!] rules directory rejected, nothing was run:"]
        for fname, line, col, problem, snippet in broken:
            where = f"{fname}" + (f", line {line}, column {col}" if line else "")
            lines.append(f"    {where}: {problem}")
            if snippet:
                lines.append(f"        found: {snippet[:100]}")
            if "cannot start any token" in problem or ">" in snippet[:3]:
                lines.append(
                    "        likely cause: a block scalar (>- or |) inside a flow mapping "
                    "{...}.\n"
                    "        YAML forbids that. Write the matcher on its own lines instead:\n"
                    "            process.command_line:\n"
                    "              regex: '(?i)^svc-'\n"
                    "        (single quotes make \\ and } literal, which is what rule regexes need)")
        for d in dups:
            lines.append(f"    {d}")
            lines.append("        an id must be unique; delete the older draft or renumber the "
                         "newer rule")
        if dups:
            lines.append(f"    Rule ids must be unique across {rules_dir}/*.yaml.")
        lines.append("    Fix the files above (or move drafts out of rules/) and re-run.")
        raise ValueError("\n".join(lines))
    return rules


# --------------------------------------------------------------------------- engine
class Engine:
    """Runs every rule over a chronologically sorted event list.

    O(rules x events) which is fine for a demo of this size; a production engine would index by
    dataset/field first and use tumbling windows on a stream.
    """

    def __init__(self, rules, events):
        self.rules = rules
        self.events = sorted(events, key=lambda e: e.get("@timestamp") or "")
        self.t0 = event_ts(self.events[0]) if self.events else dt.datetime.now(dt.timezone.utc)
        self.hits = {}          # rule.id -> list of matching events (used by `requires`)

    def run(self, now=None):
        alerts, seen_rules = [], set()
        for rule in self.rules:
            found = self._run_rule(rule)
            for a in found:
                a.pop("_events", None)
                alerts.append(a)
            if found:
                seen_rules.add(rule.id)
            self.hits[rule.id] = len(found)
        alerts.sort(key=lambda a: a["first_seen"])
        return {"alerts": self._dedup(alerts), "rules_fired": sorted(seen_rules),
                "events_scanned": len(self.events), "rules_total": len(self.rules)}

    # -- helpers -----------------------------------------------------------
    def _candidates(self, rule):
        return [e for e in self.events if rule.applies(e)]

    def _matched(self, rule):
        """Events that pass the primary condition and are not filtered out."""
        return [e for e in self._candidates(rule)
                if rule.primary_hit(e) and not rule.is_filtered(e)]

    def _key(self, ev, fields):
        parts = []
        for f in fields:
            v = ev.get(f)
            parts.append(str(v) if v not in (None, "") else "?")
        return "|".join(parts)

    def _alert(self, rule, events, extra=None, note=""):
        evs = [e for e in events if e]
        if not evs:
            return None
        first = min(event_ts(e) for e in evs if event_ts(e))
        last = max(event_ts(e) for e in evs if event_ts(e))
        ents = {}
        for f in ("user.name", "host.name", "source.ip", "destination.ip",
                  "destination.domain", "process.name", "url.path", "dns.question.name",
                  "file.path", "network.bytes", "process.command_line"):
            vals = []
            for e in evs:
                v = e.get(f)
                if v not in (None, "") and str(v) not in [str(x) for x in vals]:
                    vals.append(v)
            if vals:
                ents[f] = vals[0] if len(vals) == 1 else vals[:12]
        distinct = {}
        for f in ("user.name", "destination.port", "destination.domain", "dns.question.name"):
            s = {str(e.get(f)) for e in evs if e.get(f) not in (None, "")}
            if len(s) > 1:
                distinct[f] = sorted(s)[:25]
        a = {
            "rule_id": rule.id, "rule_name": rule.name, "severity": rule.severity,
            "confidence": rule.confidence, "risk": rule.risk, "tactic": rule.tactic,
            "technique": rule.technique, "count": len(evs),
            "first_seen": first.astimezone(dt.timezone.utc).isoformat() if first else None,
            "last_seen": last.astimezone(dt.timezone.utc).isoformat() if last else None,
            "window_seconds": int((last - first).total_seconds()) if first and last else 0,
            "event_ts": last,
            "detection_latency_s": None, "entities": ents, "distinct": distinct, "note": note,
            "sample": [(e.get("@timestamp"), e.get("event.action"),
                        str(e.get("process.command_line") or e.get("url.path")
                          or e.get("dns.question.name") or e.get("file.path") or "")[:160])
                       for e in evs[:6]],
            "_events": evs, "rule_source": rule.source,
        }
        a.update(extra or {})
        return a

    def _dedup(self, alerts):
        """Collapse same-rule + same-primary-entity repeats into one alert row."""
        out = {}
        for a in alerts:
            ent = a["entities"]
            key = (a["rule_id"], str(ent.get("source.ip")), str(ent.get("host.name")),
                   str(ent.get("user.name")))
            if key in out:
                prev = out[key]
                prev["repeat_count"] = prev.get("repeat_count", 1) + 1
                prev["count"] += a["count"]
                prev["note"] = (prev["note"] + " | repeated hit").strip(" |")
            else:
                out[key] = a
        return sorted(out.values(), key=lambda x: x["first_seen"])

    # -- rule modes --------------------------------------------------------
    def _run_rule(self, rule):
        if rule.cfg.get("time_stats"):
            return self._run_baseline(rule)
        if rule.window:
            return self._run_window(rule)
        if rule.threshold:
            alerts = self._run_threshold(rule)
            if alerts:
                return alerts
            if not rule.requires:
                return []
        matched = self._matched(rule)
        if not matched:
            return []
        if rule.requires:
            return self._run_sequence(rule, matched)
        return [a for a in (self._alert(rule, [m]) for m in matched) if a]

    def _run_threshold(self, rule):
        """Tumbling-window counts per group (optionally on a distinct field value)."""
        th = rule.threshold
        group_fields = _as_list(th.get("field") or [])
        minutes = float(th.get("window_minutes", 60))
        span = dt.timedelta(minutes=minutes)
        min_events = int(th.get("min_events", 1))
        distinct_field = th.get("distinct_field")
        min_distinct = int(th.get("min_distinct", 1))
        groups = {}
        for e in self._matched(rule):
            ts = event_ts(e)
            if ts is None:
                continue
            key = self._key(e, group_fields) if group_fields else "__all__"
            bucket = int((ts - self.t0).total_seconds() // (span.total_seconds() or 1))
            groups.setdefault((key, bucket), []).append((ts, e))
        alerts = []
        for (key, bucket), rows in sorted(groups.items(), key=lambda kv: kv[0][1]):
            if len(rows) < min_events:
                continue
            extra = {}
            if distinct_field:
                vals = {str(e.get(distinct_field)) for _, e in rows
                        if e.get(distinct_field) not in (None, "")}
                if len(vals) < min_distinct:
                    continue
                extra = {"distinct_count": len(vals), "distinct_field": distinct_field,
                         "note": f"{len(vals)} distinct {distinct_field} values in {minutes:g}m"}
            a = self._alert(rule, [e for _, e in rows], extra=extra)
            if a:
                a["threshold"] = {"min_events": min_events, "window_minutes": minutes,
                                  "observed": len(rows), "field": group_fields}
                alerts.append(a)
        return alerts

    def _run_sequence(self, rule, matched):
        req = rule.requires
        window = dt.timedelta(minutes=float(req.get("window_minutes", 60)))
        min_count = int(req.get("min_count", 1))
        key_fields = _as_list(req.get("key_fields") or rule.threshold.get("field") or [])
        prior = {}
        # build prior-event index from all events (across datasets) matching the requires condition
        for e in self.events:
            if rule.secondary_hit(e):
                prior.setdefault(self._key(e, key_fields), []).append(e)
        fired, alerts = {}, []
        for e in matched:
            key = self._key(e, key_fields) if key_fields else "__all__"
            ts = event_ts(e)
            if ts is None:
                continue
            if key in fired and (ts - fired[key]) <= window:
                continue
            cand = [p for p in prior.get(key, [])
                    if 0 <= (ts - event_ts(p)).total_seconds() <= window.total_seconds()]
            if len(cand) < min_count:
                continue
            a = self._alert(rule, [e] + cand[:2],
                            extra={"prior_events": len(cand), "sequence_window_min":
                                   req.get("window_minutes")},
                            note=f"preceded by {len(cand)} matching prior event(s) in "
                                 f"{req.get('window_minutes')}m")
            if a:
                fired[key] = ts
                alerts.append(a)
        return alerts

    def _run_window(self, rule):
        from .geo import locate
        w = rule.window
        span = dt.timedelta(minutes=float(w.get("span_minutes", 60)))
        group_fields = _as_list(w.get("group_by") or [])
        geo_field = w.get("geo_field", "source.ip")
        min_km = float(w.get("min_distance_km", 400))
        by_key = {}
        for e in self._matched(rule):
            ts, loc = event_ts(e), locate(e.get(geo_field))
            if not ts or not loc or not loc.get("coords"):
                continue
            by_key.setdefault(self._key(e, group_fields), []).append((ts, loc, e))
        alerts = []
        for key, rows in by_key.items():
            rows.sort(key=lambda r: r[0])
            for i in range(1, len(rows)):
                ts1, l1, e1 = rows[i - 1]
                ts2, l2, e2 = rows[i]
                mins = (ts2 - ts1).total_seconds() / 60.0
                if mins <= 0 or mins > span.total_seconds() / 60.0:
                    continue
                km = haversine_km(l1["coords"], l2["coords"])
                if km < min_km:
                    continue
                speed = km / (mins / 60.0) if mins else 0
                alerts.append(self._alert(
                    rule, [e1, e2],
                    extra={"geo": {"from": l1.get("label"), "to": l2.get("label"),
                                   "distance_km": round(km), "minutes": round(mins, 1),
                                   "required_speed_kmh": round(speed)},
                           "note": f"impossible travel: {round(km)} km in {round(mins)} min "
                                   f"(needs {round(speed)} km/h)"},
                    ))
                break
        return [a for a in alerts if a]

    def _run_baseline(self, rule):
        cfg = rule.cfg
        span = dt.timedelta(minutes=float(cfg.get("threshold", {}).get("window_minutes", 30)))
        min_events = int(cfg.get("threshold", {}).get("min_events", 10))
        group_fields = _as_list(cfg.get("group_by") or [])
        excludes = {p.lower() for p in _as_list(cfg.get("exclude_processes") or [])}
        stats_cfg = cfg.get("time_stats") or {}
        groups = {}
        for e in self._matched(rule):
            if (e.get("process.name") or "").lower() in excludes:
                continue
            ts = event_ts(e)
            if ts is None:
                continue
            groups.setdefault(self._key(e, group_fields), []).append((ts, e))
        alerts = []
        for key, rows in groups.items():
            if len(rows) < min_events:
                continue
            rows.sort(key=lambda r: r[0])
            if (rows[-1][0] - rows[0][0]) > span:
                # slide: keep the densest window of the group
                best, j = [], 0
                for i in range(len(rows)):
                    while rows[i][0] - rows[j][0] > span:
                        j += 1
                    if i - j + 1 > len(best):
                        best = rows[j:i + 1]
                rows = best
            if len(rows) < min_events:
                continue
            times = [r[0] for r in rows]
            deltas = [(times[i] - times[i - 1]).total_seconds() for i in range(1, len(times))]
            if not deltas:
                continue
            mean = sum(deltas) / len(deltas)
            var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
            sd = math.sqrt(var)
            cov = (sd / mean) if mean else 99
            if stats_cfg:
                if cov > float(stats_cfg.get("max_cov", 1.0)):
                    continue
                if mean < float(stats_cfg.get("min_interval_s", 0)):
                    continue
                if mean > float(stats_cfg.get("max_interval_s", 1e9)):
                    continue
            alerts.append(self._alert(
                rule, [r[1] for r in rows],
                extra={"baseline": {"groups": len(groups), "interval_mean_s": round(mean, 1),
                                    "interval_stdev_s": round(sd, 1), "cov": round(cov, 4),
                                    "threshold_cov": stats_cfg.get("max_cov"),
                                    "events_in_window": len(rows)},
                       "note": f"machine-regular polling: {len(rows)} events, mean interval "
                               f"{round(mean)}s, CoV {round(cov, 3)}"},
            ))
        return [a for a in alerts if a]


def haversine_km(a, b):
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 6371.0 * 2 * math.asin(min(1.0, math.sqrt(h)))
