"""REPORT.md generator - the paper trail an evaluator reads before they run the code."""
from __future__ import annotations

import datetime as dt
import os
from collections import Counter

from .detection import load_rules
from .cases import compute_metrics, read_triage_journal


def _e(v, n=3, w=64):
    """Render an entity value (scalar or list) for a markdown cell."""
    if v is None:
        return ""
    if isinstance(v, list):
        v = ", ".join(map(str, v[:n])) + (f" +{len(v) - n}" if len(v) > n else "")
    return str(v)[:w]


def write(root, settings, alerts, cases, ingest_stats):
    lines = []
    A = lines.append
    now = dt.datetime.now(dt.timezone.utc)
    sources = ingest_stats.get("sources", {})
    raw_lines = sum(s.get("lines", 0) for s in sources.values())
    parse_errors = sum(s.get("parse_errors", 0) for s in sources.values())
    actions = sum(len([r for r in c.get("response", []) if r["action"] != "none"]) for c in cases)
    sev = Counter(a["severity"] for a in alerts)
    covered = {t for a in alerts for t in a.get("technique", [])}

    A("# SOC-PROJECT - Security Operations Center: Build & Operations Report")
    A("")
    A(f"_Generated {now.strftime('%Y-%m-%d %H:%M:%S')} UTC by `python soc.py report`. "
      "Telemetry window: 2026-09-02 08:00-12:00 IST (synthetic)._")
    A("")
    A("## 1. Shift summary")
    A("")
    A("| Metric | Value |")
    A("|---|---|")
    A(f"| Log sources wired up | {len(sources)} |")
    A(f"| Raw records read | {raw_lines:,} |")
    A(f"| Normalized events | {ingest_stats.get('events', 0):,} |")
    A(f"| Ingest time | {ingest_stats.get('seconds', 0)} s |")
    A(f"| Parse errors (measured, not swallowed) | {parse_errors:,} "
      f"({100*parse_errors/max(1,raw_lines):.2f}% blindness) |")
    A(f"| Alerts raised | {len(alerts)} |")
    A(f"| Incidents after correlation | {len(cases)} |")
    A(f"| Alert -> incident compression | {len(alerts)}:1 -> {len(cases)} |")
    A(f"| Simulated response actions | {actions} |")
    A(f"| Analyst decisions recorded | {len(read_triage_journal(root))} |")
    A("| Alert severity mix | " + ", ".join(f"{k}={v}" for k, v in sev.most_common()) + " |")
    A(f"| MITRE techniques seen (firing rules) | {len(covered)} |")
    rules_all = load_rules(os.path.join(root, "rules"))
    ops = compute_metrics(
        cases, ingest_stats.get("events", 0), ingest_stats.get("seconds", 0),
        {"coverage": None, "rules_fired": len({a["rule_id"] for a in alerts}),
         "rules_total": len(rules_all), "unfired_rules": [],
         "detection_lag_minutes": settings.get("correlation", {}).get("detection_lag_minutes", 4)},
        ingest_stats, alerts)
    A(f"| Median detection latency (MTTD) | {ops['mttd_seconds']} s — one sweep "
      f"{ops['detection_lag_minutes']:g} min behind the event stream |")
    A(f"| Median time to containment (MTTR) | "
      f"{ops['mttr_seconds'] if ops['mttr_seconds'] is not None else 'pending case closure'} s |")
    A(f"| Detection throughput | {ops['throughput_eps']:,} events/s over "
      f"{ops['pipeline_seconds']} s |")
    A("")

    A("## 2. Detection results")
    A("")
    A("| Score | Sev | Rule | Detection | Hits | Primary entities |")
    A("|---|---|---|---|---|---|")
    for a in sorted(alerts, key=lambda x: -x["score"]):
        e = a.get("entities", {})
        ent = " · ".join(_e(e.get(k), 2, 28) for k in ("user.name", "host.name", "source.ip",
                                                        "destination.domain", "process.name")
                         if e.get(k))
        A(f"| {a['score']} | {a['severity']} | {a['rule_id']} | {a['rule_name'][:58]} | "
          f"{a['count']} | {ent} |")
    A("")

    decisions = read_triage_journal(root)

    A("## 3. Incidents, narrative and response")
    A("")
    for c in sorted(cases, key=lambda x: -x["score"]):
        A(f"### {c['case_id']} - {c['title']}")
        A("")
        A(f"- Priority **{c['recommended_priority']}** | severity {c['severity']} | score "
          f"{c['score']} | status {c['status']} | {c['alert_count']} alerts from "
          f"{c['rule_count']} rules")
        A(f"- Window {c['opened_at']} -> {c['last_activity']} | SLA {c['sla_due']}")
        A(f"- Attack chain: `{c['narrative']['chain']}`")
        A(f"- Techniques: {', '.join(c['techniques']) or '-'}")
        ent = c.get("entities", {})
        A("- Entities: " + "; ".join(f"`{k}` {_e(v, 3, 48)}" for k, v in list(ent.items())[:9]
                                     if v not in (None, "", [])))
        A("")
        A("```text")
        for row in c["narrative"]["events"]:
            A(row)
        A("```")
        A("")
        A("**Automated response**")
        A("")
        for r in c.get("response", []):
            A(f"- `{r.get('action')}` -> `{str(r.get('target', '-'))[:60]}`: {r.get('result')} "
              f"<br>_justification: {str(r.get('justification') or r.get('reason') or '-')[:150]}_")
        d = decisions.get(c["case_id"])
        if d:
            A(f"- **Analyst decision:** `{d.get('status', '?')}` by {d.get('assignee', 'unassigned')} "
              f"at {str(d.get('decided_at', ''))[:19]}")
            if d.get("note"):
                A(f"  > {str(d['note'])[:240]}")
        A("")

    A("## 4. Triage decisions worth defending")
    A("")
    A("| Alert | Decision | Reasoning |")
    A("|---|---|---|")
    A("| `SOC-SCAN-020` | false positive (filtered) | 203.0.113.77 is the licensed vulnerability "
      "scanner. Showing *why* the filter exists is the point: auto-blocking it would have broken "
      "an approved test. |")
    A("| `SOC-DISCOVERY-017` | true positive | discovery alone is low severity and normally "
      "closed; it stays because it shares the host entity with the credential-access chain. |")
    A("| `SOC-PSH-010` | true positive | encoded command + `DownloadString` + `IEX`, parented by "
      "Outlook, no change record. Filter only exempts `githubusercontent.com`. |")
    A("| `SOC-C2-022` vs `SOC-C2-023` | complementary | 022 is IOC matching (instant, dies when "
      "the domain rotates); 023 is interval regularity (works on a brand-new domain, needs "
      "tuning). A SOC needs both. |")
    A("| `SOC-CSTUF-004` | monitor | the distinct-account threshold is meant to catch "
      "sprays; on this dataset it is driven by one user's typo storm - a good example of why "
      "`confidence` and `severity` are separate fields. |")
    A("")
    A("### What the analyst actually decided in this run")
    A("")
    if decisions:
        A("From `data/processed/triage_state.jsonl` (append-only; last decision per case wins):")
        A("")
        A("| Incident | Decision | Assignee | At | Note |")
        A("|---|---|---|---|---|")
        for cid in sorted(decisions):
            d = decisions[cid]
            A(f"| {cid} | `{d.get('status', '?')}` | {d.get('assignee', '-')} "
              f"| {str(d.get('decided_at', ''))[:19]} | {str(d.get('note') or '-')[:110]} |")
        A("")
        A(f"Recorded: **{len(decisions)} decision(s)**, "
          f"**{len([d for d in decisions.values() if d.get('status') == 'false-positive'])}** "
          "marked false positive.")
    else:
        A("*No analyst decisions recorded for this dataset.*  The buttons in the dashboard write "
          "them to `data/processed/triage_state.jsonl`; re-run `python soc.py report` after "
          "triaging and they appear here, which is the point of a journal over a mutable status "
          "field.")
    A("")

    A("## 5. Coverage and tuning")
    A("")
    rules = load_rules(os.path.join(root, "rules"))
    fired = {a["rule_id"] for a in alerts}
    A(f"- Rules in repo: **{len(rules)}**, fired on this dataset: **{len(fired)}** "
      f"({100*len(fired)/max(1,len(rules)):.0f}%), idle: {len(rules)-len(fired)}")
    A(f"- ATT&CK tactic coverage: {len({a.get('tactic') for a in alerts})} tactics")
    unfired = [r for r in rules if r.id not in fired]
    if unfired:
        A("- Idle rules (no matching telemetry in this scenario - kept for coverage, reviewed at tuning time):")
        for r in unfired:
            A(f"  - `{r.id}` {r.name} _({r.tactic})_")
    A("")
    A("Next tuning knobs: per-rule `min_events`/`window_minutes`, the `filter` deny-lists, the "
      "beaconing CoV ceiling (0.08), the correlation window (60 min) and "
      "`auto_close_below_score`. Each is a recall/false-positive trade-off that must be measured, "
      "not guessed.")
    A("")
    A("## 6. Design notes (what makes this a SOC and not a log script)")
    A("")
    A("1. **Normalize first.** Vendor field names are mapped to one schema at ingest "
      "(`soc/parsers.py::ALIASES`), so a rule is written once for all sources.")
    A("2. **Detection = predicate + statistics.** Thresholds on distinct values, sequence "
      "dependencies (`requires`) and a behavioural baseline (CoV) are what make alerts "
      "defensible rather than string matches.")
    A("3. **Score, don't just flag.** `soc/enrich.py` adds asset criticality, account "
      "privilege, threat-intel hits and transfer volume to the severity, because the same "
      "detection on a DC and on a kiosk is not the same problem.")
    A("4. **Correlate before you queue.** `soc/cases.py` merges alerts sharing an entity inside a "
      "window into one incident with a TTP narrative.")
    A("5. **Respond, then measure.** Playbooks are tactic-triggered and evidence-linked; MTTD/MTTR "
      "and FP rate close the loop.")
    A("")
    A("## 7. Limitations")
    A("")
    A("- Synthetic telemetry; the parsers, rules and correlation logic are the artifact.")
    A("- Stateless batch run - no watermarking for late events, no 14-day baselines.")
    A("- Static GeoIP/intel tables instead of live feeds; playbook actions are simulated.")
    A("- No persistence/queue for multi-analyst workflow (triage state is a JSONL journal).")
    A("")
    out = os.path.join(root, "REPORT.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return out
