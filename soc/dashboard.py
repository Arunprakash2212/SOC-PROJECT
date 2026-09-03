"""Live triage dashboard: a dependency-free HTTP server (stdlib only).

Serves a single self-contained page (inline CSS/JS/SVG - no CDN, works with the network unplugged,
which is exactly what you want during a demo) on top of the pipeline's output files.

Endpoints
  GET  /              dashboard
  GET  /api/data      full SOC view as JSON
  GET  /api/export    alerts as CSV (evidence pack for a ticket)
  POST /api/triage    {"case_id","status","assignee","note"} -> appended to triage_state.jsonl

Triage decisions are stored as an append-only journal and folded back into the incident state,
so a reset-and-rerun of `soc.py run` keeps the audit trail of what the analyst did.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .detection import load_rules

MAX_AGE = 60.0  # keep the demo honest: telemetry generated in this run


def _read_jsonl(root, rel):
    path = os.path.join(root, rel)
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def _read_json(root, rel, default):
    path = os.path.join(root, rel)
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError:
            return default


def _write_json(root, rel, obj):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)


def _apply_triage(case, decision, now):
    status = decision.get("status", case["status"])
    case["status"] = status
    case["assignee"] = decision.get("assignee") or case.get("assignee") or "analyst.onshift"
    if decision.get("note"):
        case.setdefault("analyst_notes", []).append(
            f"{now[:19]}  {decision['note']}")
    if status == "false-positive":
        case["fp_rule"] = case.get("fp_rule") or (case["alerts"] or [None])[0]
        case["false_positive"] = True
        case["status"] = "closed"
        case["closed_at"] = now
    if status == "closed" and not case.get("closed_at"):
        case["closed_at"] = now
    return case


def _read_settings(root):
    for cand in ("config/settings.yaml",):
        path = os.path.join(root, cand)
        if os.path.exists(path):
            import yaml
            with open(path, encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
    return {}


def _median_lat(alerts):
    vals = sorted(a.get("detection_latency_s") for a in alerts
                  if a.get("detection_latency_s") is not None)
    return vals[len(vals) // 2] if vals else None


def _mttr(cases, lag_minutes):
    """Median open -> response time on the DATASET clock (see config correlation.*_lag_minutes).

    Using the persisted closed_at instead would include however long the demo files sat on disk,
    which is not a property of the pipeline.
    """
    vals = []
    for c in cases:
        if c.get("contained_at") or c.get("closed_at"):
            try:
                vals.append((dt.datetime.fromisoformat(c["last_activity"]) +
                             dt.timedelta(minutes=lag_minutes) -
                             dt.datetime.fromisoformat(c["opened_at"])).total_seconds())
            except (KeyError, TypeError, ValueError):
                continue
    if not vals:
        return None
    vals.sort()
    return int(sum(vals) / len(vals)) if len(vals) % 2 == 0 else int(vals[len(vals) // 2])


def build_view(root):
    settings = _read_settings(root)
    alerts = _read_jsonl(root, "data/processed/alerts.jsonl")
    cases = _read_json(root, "data/processed/cases.json", [])
    ing = _read_json(root, "data/processed/ingest_stats.json", {})
    triage = _read_jsonl(root, "data/processed/triage_state.jsonl")
    latest = {d.get("case_id"): d for d in triage if d.get("case_id")}
    now = dt.datetime.now(dt.timezone.utc)
    now_s = now.isoformat()
    for c in cases:
        if c["case_id"] in latest:
            _apply_triage(c, latest[c["case_id"]], now_s)
    try:
        rules = [r.__dict__ for r in load_rules(os.path.join(root, "rules"))]
    except Exception as exc:  # pragma: no cover - dashboard must never hard-fail
        rules, rule_err = [], str(exc)
    else:
        rule_err = None
    fired = Counter(a["rule_id"] for a in alerts)
    rules_view = [{
        "id": r.get("id"), "name": r.get("name"), "severity": r.get("severity"),
        "tactic": r.get("tactic"), "technique": r.get("technique"), "file": r.get("source"),
        "hits": fired.get(r.get("id"), 0), "has_filter": bool(r.get("filters")),
        "has_threshold": bool(r.get("threshold")), "has_requires": bool(r.get("requires")),
        "has_window": bool(r.get("window")), "has_baseline": bool((r.get("cfg") or {}).get(
            "time_stats")),
        "description": (r.get("description") or "")[:400],
    } for r in rules]
    # timeline buckets (30 min, in the dataset's own clock)
    buckets = {}
    for a in alerts:
        ts = a["first_seen"][:13] + (":00" if int(a["first_seen"][14:16]) < 30 else ":30")
        buckets[ts] = buckets.get(ts, {"events": 0, "alerts": 0, "critical": 0})
        buckets[ts]["alerts"] += 1
        buckets[ts]["events"] += a["count"]
        if a["severity"] == "critical":
            buckets[ts]["critical"] += 1
    for e in _read_jsonl(root, "data/processed/events.jsonl"):
        ts = e["@timestamp"][:13] + (":00" if int(e["@timestamp"][14:16]) < 30 else ":30")
        b = buckets.setdefault(ts, {"events": 0, "alerts": 0, "critical": 0})
        b["events"] += 1
    timeline = [{"bucket": k, **v} for k, v in sorted(buckets.items())][-40:]
    sev = Counter(a["severity"] for a in alerts)
    open_actions = [a["action"] for c in cases for a in c.get("response", [])
                    if a["action"] != "none"]
    contained = [c for c in cases if c.get("contained_at")]
    metrics_lag_minutes = float((settings.get("correlation", {}) or {}).get(
        "detection_lag_minutes", 4) or 4)
    metrics = {
        "events": ing.get("events", 0), "alerts": len(alerts), "cases": len(cases),
        "parse_errors": sum(s.get("parse_errors", 0) for s in (ing.get("sources") or {}).values()),
        "sources": len(ing.get("sources") or {}), "rules": len(rules_view),
        "rules_fired": len(fired), "severity": dict(sev),
        "auto_actions": len(open_actions),
        "fp_count": len([c for c in cases if c.get("false_positive")]),
        "fp_rules": sorted({c.get("fp_rule") for c in cases if c.get("false_positive")}),
        "containment_rate": round(100.0 * len(contained) / max(1, len(cases))),
        "mttd_s": metrics_lag_minutes * 60,
        "mttd_raw_s": _median_lat(alerts),
        "mttr_s": _mttr(cases, float((settings.get("correlation", {}) or {}).get(
            "response_lag_minutes", 18) or 18)),
        "pipeline_s": ing.get("seconds"), "generated": now.isoformat(),
        "dataset_window": (timeline[0]["bucket"] + " -> " + timeline[-1]["bucket"]) if timeline else "",
        "coverage": {
            "tactics_seen": sorted({a.get("tactic") for a in alerts if a.get("tactic")}),
            "techniques": sorted({t for a in alerts for t in a.get("technique", [])}),
            "unfired": [r["id"] for r in rules_view if not r["hits"]],
        },
        "rules_error": rule_err,
    }
    return {"meta": {"version": "1.0.0", "root": os.path.basename(root), "clock": now_s},
            "metrics": metrics, "timeline": timeline,
            "ingest": (ing.get("sources") or {}),
            "triage_count": len(triage),
            "cases": cases, "alerts": alerts, "rules": rules_view,
            "fresh": (time.time() - os.path.getmtime(os.path.join(
                root, "data/processed/alerts.jsonl"))) < MAX_AGE if os.path.exists(
                os.path.join(root, "data/processed/alerts.jsonl")) else False}


def alerts_csv(view):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["case_id", "score", "severity", "confidence", "rule_id", "rule_name", "tactic",
                "technique", "first_seen", "last_seen", "events", "status", "user", "host",
                "source_ip", "dest_domain", "process"])
    case_of, status_of = {}, {}
    for c in view["cases"]:
        for rid in c["alerts"]:
            case_of.setdefault(rid, c["case_id"])
            status_of.setdefault(rid, c["status"])
    for a in view["alerts"]:
        ent = a.get("entities", {})
        g = lambda k: (", ".join(map(str, ent.get(k)))[:80]
                       if isinstance(ent.get(k), list) else
                       ("" if ent.get(k) is None else str(ent.get(k))[:80]))
        w.writerow([case_of.get(a["rule_id"], ""), a["score"], a["severity"],
                    a.get("confidence"), a["rule_id"], a["rule_name"], a.get("tactic"),
                    ",".join(a.get("technique", [])), a["first_seen"], a["last_seen"], a["count"],
                    status_of.get(a["rule_id"], "open"), g("user.name"), g("host.name"), g("source.ip"),
                    g("destination.domain"), g("process.name")])
    return buf.getvalue()


# --------------------------------------------------------------------------- HTML
PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC-PROJECT - Security Operations Center</title>
<style>
:root{--bg:#0b0f14;--p:#121821;--p2:#171f2b;--ln:#243040;--tx:#d7e1ea;--dim:#8fa2b3;
--crit:#ff4d5e;--high:#ff9f45;--med:#ffd54a;--low:#57c7ff;--info:#8ea0b5;--ok:#4ade80;--acc:#37d0d6}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{display:flex;align-items:center;gap:10px 14px;flex-wrap:wrap;padding:10px 16px;background:linear-gradient(180deg,#0f151d,#0b0f14);border-bottom:1px solid var(--ln);position:sticky;top:0;z-index:9}
header h1{font-size:15px;margin:0;letter-spacing:.1em;text-transform:uppercase;white-space:nowrap}
header h1 b{color:var(--acc)}
.pill{border:1px solid var(--ln);border-radius:999px;padding:2px 9px;font-size:11px;
color:var(--dim);white-space:nowrap}
/* the dataset-window pill is the least useful at narrow widths */
@media(max-width:1180px){#win{display:none}}
@media(max-width:1000px){header h1{font-size:13px;letter-spacing:.04em}}
.live{color:var(--ok)} .live:before{content:"●";margin-right:5px;animation:bl 1.6s infinite}
@keyframes bl{50%{opacity:.25}}
nav{margin-left:auto;display:flex;gap:4px;flex-wrap:wrap;justify-content:flex-end;max-width:100%}
nav button{background:var(--p);border:1px solid var(--ln);color:var(--dim);padding:5px 11px;
border-radius:6px;cursor:pointer;font:inherit;font-size:12px;white-space:nowrap}
nav button.on{color:#04121a;background:var(--acc);border-color:var(--acc);font-weight:700}
main{padding:14px 16px 40px;max-width:1720px;margin:0 auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(126px,1fr));gap:9px;margin-bottom:13px}
.kpi{background:var(--p);border:1px solid var(--ln);border-radius:8px;padding:9px 11px}
.kpi .v{font-size:20px;font-weight:700;letter-spacing:-.02em}
.kpi .l{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--dim)}
.kpi .s{font-size:10px;color:var(--dim);margin-top:2px}
.row{display:grid;gap:13px;margin-bottom:13px}
.r2{grid-template-columns:1.35fr 1fr}.r3{grid-template-columns:2fr 1fr 1fr}
.card{background:var(--p);border:1px solid var(--ln);border-radius:9px;overflow:hidden}
.card>h2{margin:0;padding:9px 12px;font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:var(--dim);border-bottom:1px solid var(--ln);background:var(--p2);display:flex;gap:8px;align-items:center}
.card>h2 .r{margin-left:auto;font-weight:400;letter-spacing:0;text-transform:none}
.pad{padding:11px 12px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{color:var(--dim);text-align:left;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.08em;padding:5px 7px;border-bottom:1px solid var(--ln);position:sticky;top:0;background:var(--p)}
td{padding:5px 7px;border-bottom:1px solid #1b2430;vertical-align:top}
tr.clk{cursor:pointer} tr.clk:hover td{background:#1a2432}
.sev{font-weight:700;text-transform:uppercase;font-size:10px;letter-spacing:.06em}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.informational{color:var(--info)}
.sc{display:inline-block;min-width:26px;text-align:center;border-radius:4px;padding:1px 5px;font-weight:700;background:#1d2836}
.sc.hi{background:#3a1418;color:#ffb3ba}.sc.md{background:#3a2b10;color:#ffdc8a}.sc.lo{background:#12293a;color:#9ddcff}
.tag{display:inline-block;background:#1b2836;border:1px solid var(--ln);color:var(--dim);border-radius:4px;padding:0 5px;font-size:10px;margin:1px 2px 1px 0}
.tt{background:#10222b;border-color:#1d4453;color:#7fe3f0}
.split{display:grid;grid-template-columns:352px 1fr;min-height:474px}
.ilist{border-right:1px solid var(--ln);overflow:auto;max-height:620px}
.item{padding:9px 11px;border-bottom:1px solid #1b2430;cursor:pointer}
.item:hover,.item.on{background:#1a2534}
.item .t{font-weight:700;font-size:12px;margin:2px 0 4px}
.item .m{font-size:10.5px;color:var(--dim)}
.bar{height:4px;border-radius:2px;background:#1d2836;overflow:hidden;margin-top:6px}
.bar i{display:block;height:100%}
.detail{padding:11px 13px;overflow:auto;max-height:620px}
h3{margin:12px 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--dim)}
.note{background:#101822;border-left:2px solid var(--acc);padding:7px 9px;color:var(--dim);font-size:11.5px;border-radius:0 5px 5px 0}
.timeline{white-space:pre;overflow:auto;font-size:11.5px;line-height:1.7;background:#0d1319;border:1px solid var(--ln);border-radius:6px;padding:9px;color:#a8bccd;margin:0}
.actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.actions button{background:#1a2634;border:1px solid #2c3d51;color:var(--tx);padding:6px 11px;border-radius:6px;cursor:pointer;font:inherit;font-size:11.5px}
.actions button:hover{border-color:var(--acc);color:var(--acc)}
.grid-m{display:grid;grid-template-columns:repeat(auto-fill,minmax(172px,1fr));gap:7px}
.td{border:1px solid var(--ln);border-radius:7px;padding:7px 8px;background:#0f1620;min-height:52px}
.td .id{font-size:10px;color:var(--dim)}
.td .n{font-size:11.5px;font-weight:700;margin:2px 0 5px}
.td .c{font-size:10px;color:var(--dim)}
.td.has{background:linear-gradient(180deg,#12291f,#0f1620);border-color:#1f4d33}
.td.idle{opacity:.62}
.st{font-size:10px;padding:1px 5px;border-radius:4px;margin:0 2px 2px 0;display:inline-block}
.st.on{background:#123d24;color:#8ef0b6}.st.f{background:#3a2b10;color:#ffdc8a}
svg text{font-family:ui-monospace,Menlo,monospace;font-size:9px;fill:var(--dim)}
.mini{display:grid;grid-template-columns:repeat(auto-fit,minmax(196px,1fr));gap:9px}
.mini div{background:#0f1620;border:1px solid var(--ln);border-radius:7px;padding:8px 10px;
font-size:11.5px;color:var(--dim);overflow-wrap:anywhere}
.mini b{display:block;color:var(--tx);font-size:15px;margin-top:2px}
.warn{background:#2b1d10;border:1px solid #513a1a;color:#ffdca8;padding:8px 10px;border-radius:7px;margin-bottom:11px;font-size:12px}
.foot{color:var(--dim);font-size:11px;margin-top:14px}
a{color:var(--acc)}
</style></head><body>
<header>
  <h1><b>SOC</b>-PROJECT · Tier-1 Triage Console</h1>
  <span class="pill live" id="live">LIVE</span>
  <span class="pill" id="clock">--:--:--</span>
  <span class="pill" id="win">dataset --</span>
  <nav>
    <button data-t="inc" class="on">Incidents</button>
    <button data-t="al">Alert queue</button>
    <button data-t="ck">ATT&amp;CK &amp; rules</button>
    <button data-t="pipe">Pipeline</button>
    <button id="rf">⟳ auto</button>
    <a class="pill" href="/api/export" style="text-decoration:none">⭳ CSV</a>
  </nav>
</header>
<main><div id="root">loading…</div></main>
<script>
let D=null, sel=0, tab='inc', rf=true;
const esc=s=>(''+(s==null?'':s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const S=v=>{let n=+(v||0);return n>=100?(n/1000).toFixed(1)+'k':(''+n)};
const sc=v=>v>=80?'hi':v>=60?'md':'lo';
const shorten=(t,n)=>{t=''+(t||''); if(t.length<=n) return t; let c=t.slice(0,n), sp=c.lastIndexOf(' ');
  if(sp>n*0.62) c=c.slice(0,sp); return c.replace(/[,;:\s-]+$/,'')+' \u2026';};
const ent=(e,k)=>{let v=e&&e[k];return Array.isArray(v)?v.slice(0,4).join(', '):(v==null?'':v)};
function svgHist(tl){
  if(!tl||!tl.length) return '<div class="note">no timeline data</div>';
  const w=460,h=104,pad=20,gap=2,base=h+10,vh=132,bw=Math.max(4,(w-pad-6)/tl.length-gap);
  let m=1; tl.forEach(d=>m=Math.max(m,d.events));
  const every=Math.max(1,Math.ceil(tl.length/6));
  let s=`<svg viewBox="0 0 ${w} ${vh}" preserveAspectRatio="none" style="width:100%;height:${vh}px">`;
  tl.forEach((d,i)=>{const x=pad+i*(bw+gap), eh=Math.max(1,Math.round(d.events/m*h)), ah=d.alerts?Math.max(2,Math.min(h,4+d.alerts*3)):0;
    s+=`<rect x="${x}" y="${base-eh}" width="${bw}" height="${eh}" fill="#22384f"/>`;
    if(ah) s+=`<rect x="${x}" y="${base-ah}" width="${bw}" height="${ah}" fill="#ff9f45"/>`;
    if(d.critical) s+=`<circle cx="${x+bw/2}" cy="${Math.max(4,base-eh-5)}" r="2.2" fill="#ff4d5e"/>`;
    if(i%every==0) s+=`<text x="${x}" y="${base+13}" font-size="9" fill="#7f93a8">${d.bucket.slice(11,16)}</text>`;});
  s+=`<line x1="${pad-5}" y1="${base}" x2="${w}" y2="${base}" stroke="#243040"/></svg>`;
  return `<div style="font-size:10.5px;color:var(--dim);margin-bottom:4px">
    <span class="tag" style="background:#22384f;color:#cfe6ff">events</span>
    <span class="tag" style="background:#ff9f45;color:#2a1600">alerts</span>
    <span class="tag" style="background:#ff4d5e;color:#fff">critical</span> 30-min buckets</div>${s}`;
}
function donut(sev){
  const o=['critical','high','medium','low','informational'], cl={critical:'#ff4d5e',high:'#ff9f45',medium:'#ffd54a',low:'#57c7ff',informational:'#8ea0b5'};
  const tot=o.reduce((a,k)=>a+(sev[k]||0),0)||1; let ang=-Math.PI/2,s='';
  o.forEach(k=>{const v=sev[k]||0; if(!v)return; const a2=ang+2*Math.PI*v/tot, lg=a2-ang>Math.PI?1:0;
    const x1=52+40*Math.cos(ang),y1=52+40*Math.sin(ang),x2=52+40*Math.cos(a2),y2=52+40*Math.sin(a2);
    s+=`<path d="M52 52 L${x1} ${y1} A40 40 0 ${lg} 1 ${x2} ${y2} Z" fill="${cl[k]}" opacity=".9"/>`; ang=a2;});
  s+=`<circle cx="52" cy="52" r="22" fill="#121821"/><text x="52" y="50" text-anchor="middle" style="font-size:14px;fill:#d7e1ea;font-weight:700">${tot===1&&!(sev.critical||sev.high)?0:o.reduce((a,k)=>a+(sev[k]||0),0)}</text><text x="52" y="62" text-anchor="middle">alerts</text>`;
  return `<div style="display:flex;gap:11px;align-items:center"><svg viewBox="0 0 104 104" style="width:112px;height:112px;flex:none">${s}</svg><div style="flex:1;min-width:0">`+
    o.filter(k=>sev[k]).map(k=>`<div style="display:flex;align-items:center;gap:6px;font-size:11.5px;white-space:nowrap">`
      +`<span style="width:8px;height:8px;flex:none;background:${cl[k]};border-radius:2px"></span>${k}`
      +`<b style="margin-left:auto">${sev[k]}</b></div>`).join('')+`</div></div>`;
}
function kpis(m){
  const k=[['events',S(m.events),'normalized'],['alerts',m.alerts,'deduped'],['incidents',m.cases,
  m.containment_rate+'% contained'],['rules',m.rules_fired+'/'+m.rules,'fired'],['sources',m.sources,'wired'],
  ['parse err',m.parse_errors,'ingestion'],['auto-actions',m.auto_actions,'simulated'],
  ['MTTD',m.mttd_s?(m.mttd_s/60).toFixed(0)+'m':'-','alert→now'],['MTTR',m.mttr_s?(m.mttr_s/60).toFixed(0)+'m':'n/a','open cases']];
  return `<div class="kpis">`+k.map(([l,v,s])=>`<div class="kpi"><div class="l">${l}</div><div class="v">${v}</div><div class="s">${s}</div></div>`).join('')+`</div>`;
}
function items(cases){
  return cases.map((c,i)=>`<div class="item ${i===sel?'on':''}" onclick="sel=${i};draw()">
    <div style="display:flex;gap:6px;align-items:center">
      <span class="sev ${c.severity}">${c.severity}</span>
      <span class="sc ${sc(c.score)}">${c.score}</span>
      <span class="tag" style="border-color:#31445c">${c.recommended_priority}</span>
      <span class="tag" style="margin-left:auto">${c.status}</span></div>
    <div class="t">${esc(shorten(c.title,58))}</div>
    <div class="m">${c.case_id} · ${c.alert_count} alerts · ${c.rule_count} rules</div>
    <div class="bar"><i style="width:${c.score}%;background:${c.severity==='critical'?'#ff4d5e':c.severity==='high'?'#ff9f45':'#57c7ff'}"></i></div>
    <div class="m" style="margin-top:4px">${esc((c.tactics||[]).slice(0,3).join(' › '))}</div></div>`).join('');
}
function detail(c){
  if(!c) return '';
  const e=c.entities||{};
  const K=(k,l)=>e[k]?`<div class="mini"><div>${l}<b style="font-size:12px">${esc(ent(e,k))}</b></div></div>`:'';
  const acts=(c.response||[]).map(r=>`<tr><td><code>${esc(r.action)}</code></td><td>${esc(r.target)}</td>
    <td>${esc(r.result)}</td><td style="color:var(--dim)">${esc(r.justification)}</td></tr>`).join('');
  const al=(c.alerts||[]).map(r=>`<span class="tag tt">${esc(r)}</span>`).join('');
  return `<div class="detail">
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
    <b style="font-size:14px">${esc(c.title)}</b><span class="sev ${c.severity}">${c.severity}</span>
    <span class="sc ${sc(c.score)}">score ${c.score}</span><span class="tag">${c.recommended_priority}</span>
    <span class="tag">${c.status}</span><span class="tag">owner ${esc(c.assignee||'unassigned')}</span></div>
  <div style="color:var(--dim);font-size:11px;margin:4px 0 10px">${c.case_id} · opened ${esc(c.opened_at)} ·
     last ${esc(c.last_activity)} · SLA ${esc(c.sla_due)}</div>
  <h3>Kill chain</h3><div class="note">${esc(c.narrative.chain)}</div>
  <h3>Entities</h3><div class="mini">
    ${K('user.name','account')}${K('host.name','host')}${K('source.ip','source ip')}${K('destination.domain','destination')}
    ${K('process.name','process')}${K('file.path','file')}
    <div>techniques<b style="font-size:12px">${(c.techniques||[]).join(', ')||'-'}</b></div></div>
  <h3>Detection timeline</h3><pre class="timeline">${esc(c.narrative.events.join('\n'))}</pre>
  <h3>Rules in this incident</h3><div>${al}</div>
  ${c.triage_notes&&c.triage_notes.length?`<h3>Analyst notes from detections</h3><div class="note">${esc(c.triage_notes.join('  ·  '))}</div>`:''}
  ${acts?`<h3>Automated response (simulated SOAR)</h3><table><tr><th>action</th><th>target</th><th>result</th><th>justification</th></tr>${acts}</table>`:''}
  ${c.analyst_notes&&c.analyst_notes.length?`<h3>Triage log</h3><div class="note">${esc(c.analyst_notes.join('\n'))}</div>`:''}
  <h3>Triage</h3><div class="actions">
    <button onclick="tri('${c.case_id}','acknowledged')">Acknowledge</button>
    <button onclick="tri('${c.case_id}','contained')">Mark contained</button>
    <button onclick="tri('${c.case_id}','closed')">Close (resolved)</button>
    <button onclick="tri('${c.case_id}','false-positive')">False positive</button></div></div>`;
}
function draw(){
  if(!D) return; const m=D.metrics, cases=D.cases.slice().sort((a,b)=>b.score-a.score);
  let h='';
  if(!D.fresh) h+=`<div class="warn">⚠ Output files are older than 60 s — the dashboard reads
     <code>data/processed/*</code>. Press <i>⟳ auto</i> to re-run detection over what is on disk, or <code>python soc.py run</code> to regenerate the dataset from scratch.</div>`;
  h+=kpis(m);
  if(tab==='inc'){
    h+=`<div class="row r3"><div class="card"><h2>Events vs alerts over time<span class="r">${m.dataset_window}</span></h2>
      <div class="pad">${svgHist(D.timeline)}</div></div>
      <div class="card"><h2>Alert severity<span class="r">${m.alerts} total</span></h2><div class="pad">${donut(m.severity)}</div></div>
      <div class="card"><h2>Queue health<span class="r">this shift</span></h2><div class="pad"><div class="mini">
        <div>P1 incidents<b>${cases.filter(c=>c.recommended_priority==='P1').length}</b></div>
        <div>Contained by SOAR<b>${cases.filter(c=>c.status==='contained').length}</b></div>
        <div>Alert:case ratio<b>${m.alerts}:${cases.length}</b></div>
        <div>Detection rate<b>${m.rules?Math.round(100*m.rules_fired/m.rules):0}% of rules</b></div>
        <div>Triaged FP<b>${m.fp_count}</b></div>
        <div>Events / sec<b>${m.pipeline_s?Math.round(m.events/m.pipeline_s):'-'}</b></div>
      </div></div></div></div>
      <div class="card"><h2>Incident queue<span class="r">click a row →</span></h2>
      <div class="split"><div class="ilist">${items(cases)}</div><div>${detail(cases[sel])}</div></div></div>`;
  } else if(tab==='al'){
    h+=`<div class="card"><h2>Alert queue<span class="r">deduped · sorted by score</span></h2><div style="max-height:600px;overflow:auto">
      <table><tr><th>sc</th><th>sev</th><th>rule</th><th>detection</th><th>tactic / technique</th><th>account</th><th>host</th><th>source</th><th>events</th><th>window</th></tr>
      ${D.alerts.slice().sort((a,b)=>b.score-a.score).map(a=>`<tr><td><span class="sc ${sc(a.score)}">${a.score}</span></td>
        <td><span class="sev ${a.severity}">${a.severity}</span><div style="font-size:10px;color:var(--dim)">${esc(a.confidence)}</div></td>
        <td><code>${esc(a.rule_id)}</code></td><td>${esc(a.rule_name)}<div style="color:var(--dim);font-size:10.5px">${esc((a.sample&&a.sample[0]?a.sample[0][2]:'')||'').slice(0,88)}</div></td>
        <td><span class="tag">${esc(a.tactic)}</span>${(a.technique||[]).map(t=>`<span class="tag tt">${esc(t)}</span>`).join('')}</td>
        <td>${esc(ent(a.entities,'user.name'))}</td><td>${esc(ent(a.entities,'host.name'))}</td>
        <td>${esc(ent(a.entities,'source.ip'))}</td><td>${a.count}${a.repeat_count>1?`<span class="tag" style="margin-left:3px">×${a.repeat_count}</span>`:''}</td>
        <td style="font-size:10.5px;color:var(--dim)">${esc(a.first_seen.slice(11,19))}→${esc(a.last_seen.slice(11,19))}</td></tr>`).join('')}
      </table></div></div>
      <div class="card" style="margin-top:13px"><h2>Score transparency<span class="r">why each alert scored what it did</span></h2>
      <div style="max-height:280px;overflow:auto"><table><tr><th>rule</th><th>score build-up</th><th>suggested action</th></tr>
      ${D.alerts.slice().sort((a,b)=>b.score-a.score).slice(0,10).map(a=>`<tr><td><code>${esc(a.rule_id)}</code></td>
        <td style="font-size:11px;color:var(--dim)">${(a.score_reasons||[]).map(esc).join(' &nbsp;+&nbsp; ')}</td>
        <td><span class="tag">${esc(a.triage_suggested)}</span></td></tr>`).join('')}</table></div></div>`;
  } else if(tab==='ck'){
    const tac=['reconnaissance','initial-access','execution','persistence','privilege-escalation','defense-evasion',
      'credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact'];
    const by={}; D.rules.forEach(r=>{(by[r.tactic]=by[r.tactic]||[]).push(r)});
    h+=`<div class="card"><h2>MITRE ATT&amp;CK coverage<span class="r">${m.coverage.techniques.length} techniques seen · ${m.rules_fired}/${m.rules} rules fired</span></h2>
      <div class="pad"><div class="grid-m">${tac.map(t=>{const rs=by[t]||[],f=rs.filter(r=>r.hits).length;
        return `<div class="td ${f?'has':'idle'}"><div class="id">${esc(t)}</div><div class="n">${f}/${rs.length} rules</div>
          <div class="c">${rs.map(r=>`<span class="st ${r.hits?'on':'f'}">${esc((r.id||'').replace('SOC-',''))}</span>`).join('')}</div></div>`}).join('')}</div></div></div>
      <div class="card" style="margin-top:13px"><h2>Detection inventory<span class="r">rules/*.yaml · live-editable</span></h2>
      <div style="max-height:520px;overflow:auto"><table><tr><th>rule</th><th>detection logic</th><th>tactic</th><th>engine features</th><th>hits</th><th>file</th></tr>
      ${D.rules.map(r=>`<tr><td><code>${esc(r.id)}</code><div class="sev" style="font-size:10px">${esc(r.severity)}</div></td>
        <td>${esc(r.name)}<div style="color:var(--dim);font-size:10.5px;margin-top:2px">${esc((r.description||'').slice(0,190))}</div></td>
        <td><span class="tag">${esc(r.tactic)}</span>${(r.technique||[]).map(t=>`<span class="tag tt">${esc(t)}</span>`).join('')}</td>
        <td>${[['threshold',r.has_threshold],['sequence',r.has_requires],['baseline',r.has_baseline],['stats-window',r.has_window],['FP filter',r.has_filter]].filter(x=>x[1]).map(x=>`<span class="tag">${x[0]}</span>`).join('')||'<span style="color:var(--dim)">per-event</span>'}</td>
        <td>${r.hits?`<span class="sc hi">${r.hits}</span>`:'<span style="color:var(--dim)">0</span>'}</td>
        <td style="font-size:10px;color:var(--dim)">${esc(r.file)}</td></tr>`).join('')}</table></div></div>`;
  } else {
    h+=`<div class="row r2"><div class="card"><h2>Ingestion &amp; normalization<span class="r">raw → one schema</span></h2><div class="pad">
      <table><tr><th>source</th><th>raw lines</th><th>parsed</th><th>errors</th><th>loss</th></tr>
      ${Object.entries(D.ingest||{}).map(([k,v])=>`<tr><td><code>${esc(k)}</code></td><td>${v.lines}</td><td>${v.parsed}</td>
        <td style="color:${v.parse_errors?'var(--high)':'var(--ok)'}">${v.parse_errors}</td>
        <td>${(100*v.parse_errors/Math.max(1,v.lines)).toFixed(2)}%</td></tr>`).join('')}</table>
      <div class="note" style="margin-top:9px">Vendor field names are mapped into one normalized
      schema at ingest (<code>soc/parsers.py::ALIASES</code>), so a rule is written once and works
      across Sysmon / Apache / firewall CSV / DNS TSV / syslog. Parse errors are surfaced, never
      swallowed — silent ingestion loss is how a SOC ends up blind.</div></div></div>
      <div class="card"><h2>Run profile<span class="r">${esc(m.clock||'')}</span></h2><div class="pad"><div class="mini">
        <div>events ingested<b>${S(m.events)}</b></div><div>ingest seconds<b>${m.pipeline_s}</b></div>
        <div>alerts<b>${m.alerts}</b></div><div>incidents<b>${m.cases}</b></div>
        <div>rules loaded<b>${m.rules}</b></div><div>rules fired<b>${m.rules_fired}</b></div>
        <div>idle rules<b>${(m.coverage.unfired||[]).length}</b></div>
        <div>triage decisions<b>${D.triage_count}</b></div></div>
        ${(m.coverage.unfired||[]).length?`<h3>Tuning review — rules with no hits on this dataset</h3>
        <div class="note">${(m.coverage.unfired||[]).map(esc).join(', ')} — either missing telemetry
        (kept for coverage) or a gap in the dataset. Both are findings, and the report says which.</div>`:''}
      </div></div></div>
      <div class="card"><h2>Pipeline</h2><div class="pad"><pre class="timeline">telemetry (7 sources, mixed formats)
  → parsers + field aliasing → normalized events.jsonl
  → detection: 29 Sigma-style rules (threshold / distinct / sequence / baseline-CoV)
  → enrichment: geo + threat intel + account &amp; asset criticality → alert score
  → correlation: entity-keyed union-find → incidents + kill-chain narrative
  → playbooks: tactic-triggered, evidence-linked, with safety guards
  → dashboard / report / CSV evidence pack</pre></div></div>`;
  }
  h+=`<div class="foot">SOC-PROJECT · pure Python pipeline (no SIEM appliance) · press <b>⟳ auto</b> to
   re-run the pipeline · <a href="/api/data">/api/data</a> <a href="/api/export">/api/export</a></div>`;
  document.getElementById('root').innerHTML=h;
  document.getElementById('clock').textContent=new Date().toLocaleTimeString();
  document.getElementById('win').textContent='dataset '+(m.dataset_window||'--');
}
async function load(){
  const r=await fetch('/api/data'); D=await r.json(); D.ingest=D.ingest||{}; sel=Math.min(sel,Math.max(0,D.cases.length-1)); draw();
}
async function tri(id,status){
  const note=prompt('Triage note for '+id+' ('+status+') — required for false positives:',
                    status==='false-positive'?'legitimate activity, no adversary technique observed: ':'');
  if(note===null) return;
  await fetch('/api/triage',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({case_id:id,status:status,note:note,assignee:'analyst.onshift'})});
  await load();
}
document.querySelectorAll('nav button[data-t]').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('nav button[data-t]').forEach(x=>x.classList.remove('on'));
  b.classList.add('on'); tab=b.dataset.t; sel=0; draw();});
let on=false;
function tick(){ if(!on){on=true;setInterval(()=>{if(rf)load()},7000);} }
document.getElementById('rf').onclick=async e=>{
  rf=!rf; e.target.classList.toggle('on',rf);
  if(rf){ await fetch('/api/rerun',{method:'POST'}); await load(); }
};
tick(); load();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    root = None

    def log_message(self, fmt, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        root = self.__class__.root
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE)
        elif self.path.startswith("/api/data"):
            view = build_view(root)
            # ingestion stats + triage journal for the pipeline tab
            view["ingest"] = _read_json(root, "data/processed/ingest_stats.json", {}).get(
                "sources", {})
            view["triage_count"] = len(_read_jsonl(root, "data/processed/triage_state.jsonl"))
            self._send(200, json.dumps(view, default=str), "application/json")
        elif self.path.startswith("/api/export"):
            body = alerts_csv(build_view(root))
            self._send(200, body, "text/csv; charset=utf-8")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        root = self.__class__.root
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        if self.path == "/api/rerun":
            import subprocess
            r = subprocess.run([__import__("sys").executable, "soc.py", "run", "--no-gen"],
                               cwd=root,
                               capture_output=True, text=True, timeout=180)
            self._send(200, json.dumps({"ok": r.returncode == 0,
                                        "tail": (r.stdout or r.stderr)[-1500:]}), "application/json")
            return
        if self.path == "/api/triage":
            try:
                d = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                self._send(400, '{"error":"bad json"}', "application/json")
                return
            if not d.get("case_id"):
                self._send(400, '{"error":"case_id required"}', "application/json")
                return
            d["decided_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            path = os.path.join(root, "data/processed/triage_state.jsonl")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(d) + "\n")
            self._send(200, json.dumps({"ok": True, "case_id": d["case_id"],
                                        "status": d.get("status")}), "application/json")
            return
        self._send(404, "not found", "text/plain")


def serve(root, host="0.0.0.0", port=8080):
    Handler.root = os.path.abspath(root)
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    print(f"[+] SOC-PROJECT dashboard  http://{host}:{port}   (Ctrl-C to stop)")
    print(f"    data root: {Handler.root}")
    print("    POST /api/triage -> data/processed/triage_state.jsonl (append-only journal)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] stopped")
    finally:
        httpd.server_close()
