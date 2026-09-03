"""`python soc.py demo` - a narrated console walkthrough of the incident.

Handy when presenting: it prints the attack story in the order the SOC would have seen it.
"""
from __future__ import annotations

import json
import os


def walkthrough(root):
    def load(rel):
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            return None
        if path.endswith(".jsonl"):
            with open(path, encoding="utf-8") as fh:
                return [json.loads(l) for l in fh if l.strip()]
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    ing = load("data/processed/ingest_stats.json") or {}
    alerts = load("data/processed/alerts.jsonl") or []
    cases = load("data/processed/cases.json") or []
    sources = ing.get("sources", {})
    print("\n=== SOC-PROJECT demo walkthrough ====================================\n")
    print("[1] INGESTION")
    print(f"    {ing.get('events','?')} normalized events from "
          f"{len(sources)} sources "
          f"({', '.join(sorted(sources))}), {ing.get('seconds','?')}s")
    print("    every vendor field renamed into one schema -> rules never care about log format\n")
    print("[2] DETECTION")
    print(f"    {len(alerts)} alerts raised; scoring combines severity + asset criticality +\n"
          f"    account privilege + threat intel + transfer volume\n")
    for a in sorted(alerts, key=lambda x: -x["score"])[:8]:
        print(f"      {a['score']:>3}  {a['severity']:<9} {a['rule_id']:<16} "
              f"{a['rule_name'][:58]}")
    print("\n[3] CORRELATION")
    print(f"    {len(cases)} incident(s) - one row per analyst problem, not per alert\n")
    for c in sorted(cases, key=lambda x: -x["score"])[:2]:
        print(f"    {c['case_id']}  {c['recommended_priority']}  score {c['score']}  "
              f"{c['status']}")
        print(f"    {c['title']}")
        print(f"    chain: {c['narrative']['chain']}")
        for row in c["narrative"]["events"]:
            print("      " + row)
        print("    response:")
        for r in c.get("response", []):
            print(f"      - {r['action']:<26} {str(r['target'])[:34]:<34} {r['result'][:48]}")
    print("\n[4] METRICS")
    crit = len([a for a in alerts if a["severity"] == "critical"])
    print(f"    {len(alerts)} alerts -> {len(cases)} incidents; {crit} critical detections")
    print("    open `python soc.py serve` for the live triage board\n")
    return 0
