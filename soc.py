#!/usr/bin/env python3
"""SOC-PROJECT CLI - one command per stage of the SOC workflow.

    python soc.py gen      # synthetic multi-source telemetry
    python soc.py ingest   # parse + normalize into one event schema
    python soc.py rules    # validate + list detection rules
    python soc.py detect   # run rules, score and enrich alerts
    python soc.py cases    # dedup, correlate into incidents, run playbooks
    python soc.py stats    # coverage + tuning report
    python soc.py report   # write REPORT.md
    python soc.py run      # all of the above (the demo)
    python soc.py serve    # live triage dashboard on http://localhost:8080
    python soc.py demo     # narrated 5-minute walkthrough of the incident
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
import time
import traceback

for _stream in (sys.stdout, sys.stderr):
    try:  # Windows console may default to cp1252; the CLI prints box-drawing/arrows
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    import yaml  # noqa: E402  (the one third-party dependency: rules/config are YAML)
except ModuleNotFoundError:
    sys.exit(
        "\n[!] Missing dependency: PyYAML (module name 'yaml').\n"
        f"    This interpreter: {sys.executable}\n"
        "    Fix:   python -m pip install -r requirements.txt\n"
        "    or:    py -3 -m pip install pyyaml\n"
        "    (Use -m pip so it installs into the SAME interpreter you are running;\n"
        "     on Windows 'pip install' alone can target a different Python.)\n"
    )

from soc import cases as cases_mod  # noqa: E402
from soc import detection, enrich, parsers, report as report_mod, telemetry  # noqa: E402


# ------------------------------------------------------------------ plumbing
def _require_project():
    """Fail with instructions instead of a traceback if you ran soc.py from elsewhere."""
    missing = [d for d in ("rules", "config", "soc")
               if not os.path.isdir(os.path.join(ROOT, d))]
    if missing:
        sys.exit(
            "\n[!] This is not the SOC-PROJECT project root - missing: %s\n"
            "    Project root: %s\n"
            "    cd into it first. On Windows/PowerShell quote paths that contain spaces, e.g.\n"
            '      cd "C:\\Users\\you\\Documents\\project\\soc project"\n'
            "    then:  python soc.py run\n" % (", ".join(missing), ROOT))


def load_settings(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def p(root, rel):
    return os.path.join(root, rel)


def _drive(path):
    return os.path.splitdrive(os.path.abspath(path))[0] or "."


def _space_guard(root, need=30 * 1024 * 1024):
    """Refuse to start a write the volume obviously cannot hold.

    On a RAM disk or a nearly full thumb drive the dataset write dies silently
    and the failure only surfaces three stages later as a JSON error in a file
    nobody wrote on purpose. Checking here turns that into one clear message.
    """
    try:
        free = shutil.disk_usage(root).free
    except OSError:  # odd filesystems: don't block the run over a stat failure
        return None
    if free < need:
        raise ValueError(
            f"[!] not enough free space on {_drive(root)}: {free / 1e6:.0f} MB free, this run needs "
            f"about {need / 1e6:.0f} MB (telemetry, normalized events, alerts).\n"
            "    Move the project onto a normal disk - a folder inside Documents is fine - or free "
            "space, then re-run:  python soc.py run")
    return free


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for num, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                # a bare json error ("Unterminated string starting at line 1...") tells the
                # operator nothing, so name the file, how much of it is usable and the fix
                raise ValueError(
                    f"[!] {os.path.basename(path)} is corrupt at line {num} (byte {exc.pos}): "
                    f"{exc.msg}.\n"
                    f"    {os.path.getsize(path)} bytes on disk, {len(out)} complete record(s) before "
                    "the bad line - a half-written file, not a bad rule.\n"
                    f"    Usually a full or removable volume ({_drive(path)}). Rebuild it with:  "
                    "python soc.py run") from None
    return out


def write_jsonl(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    written = 0
    try:
        with open(path, "w", encoding="utf-8") as fh:
            for r in rows:
                line = json.dumps(r, default=str) + "\n"
                fh.write(line)
                written += len(line.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())  # surface a full volume here, not in the next stage
    except OSError as exc:
        raise ValueError(
            f"[!] could not finish writing {os.path.basename(path)} on {_drive(path)}: "
            f"{exc.strerror or exc}.\n"
            f"    only {os.path.getsize(path) if os.path.exists(path) else 0} bytes reached the disk "
            f"({written} expected).\n"
            "    Free space on that volume - or move the project off the removable/RAM drive - and "
            "re-run:  python soc.py run") from None


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)


# ------------------------------------------------------------------ stages
def cmd_gen(args):
    settings = load_settings(p(args.root, args.config))
    outdir = p(args.root, settings["paths"]["telemetry"])
    _space_guard(args.root)
    print(f"[*] generating telemetry for {args.events} benign events + attack chain -> {outdir}")
    res = telemetry.generate(outdir, events=args.events, seed=args.seed, hours=args.hours)
    total = 0
    for name, (path, rows) in sorted(res.items()):
        size = os.path.getsize(path)
        total += rows
        print(f"    {name:9s} {rows:6d} rows  {size/1024:8.1f} KB  {os.path.basename(path)}")
    print(f"[+] {total} raw records written across {len(res)} log sources")
    return 0


def cmd_ingest(args):
    settings = load_settings(p(args.root, args.config))
    tdir = p(args.root, settings["paths"]["telemetry"])
    out = []
    stats = {}
    missing = []
    t0 = time.time()
    for name, spec in settings["sources"].items():
        path = os.path.join(tdir, spec["file"])
        if not os.path.exists(path):
            missing.append((name, spec["file"]))
            continue
        events, st = parsers.read_source(__import__("pathlib").Path(path), spec)
        stats[name] = st
        out.extend(events)
    out.sort(key=lambda e: e.get("@timestamp") or "")
    _space_guard(args.root)
    dest = p(args.root, settings["paths"]["events"])
    write_jsonl(dest, out)
    errs = sum(s["parse_errors"] for s in stats.values())
    print(f"[+] ingested {len(out)} normalized events in {time.time()-t0:.2f}s "
          f"({errs} parse errors, {100*errs/max(1,sum(s['lines'] for s in stats.values())):.2f}% loss)")
    for name, s in sorted(stats.items()):
        print(f"    {name:9s} lines={s['lines']:6d} parsed={s['parsed']:6d} "
              f"errors={s['parse_errors']:3d}")
    if missing:
        if len(missing) == len(settings["sources"]):
            # a fresh checkout ships no telemetry at all: say it once, not N times
            print(f"[!] no telemetry in {tdir} - nothing was ingested.\n"
                  "    generate the dataset first:  python soc.py run"
                  "   (logs only:  python soc.py gen)")
        else:
            for name, fname in missing:
                print(f"[!] skipped missing source {name}: {fname}"
                      "   - python soc.py gen regenerates data/telemetry")
    write_json(p(args.root, "data/processed/ingest_stats.json"),
               {"events": len(out), "seconds": round(time.time() - t0, 3), "sources": stats})
    return 0


def cmd_rules(args):
    settings = load_settings(p(args.root, args.config))
    rdir = args.rules_dir or settings.get("rules_dir", "rules")
    rules = detection.load_rules(p(args.root, rdir))
    print(f"[+] {len(rules)} detection rules loaded and validated from {rdir}/")
    by_tactic = {}
    for r in rules:
        by_tactic.setdefault(r.tactic, []).append(r)
    for tactic, rows in sorted(by_tactic.items(), key=lambda kv: -len(kv[1])):
        print(f"  {tactic:22s} {len(rows):2d}  " +
              ", ".join(f"{r.id.split('-')[1]}" for r in rows))
    print(f"  {len({t for r in rules for t in r.technique})} distinct MITRE techniques covered")
    return 0


def cmd_detect(args):
    settings, events = _load_events(args)
    session_start = dt.datetime.now(dt.timezone.utc)
    rules = detection.load_rules(p(args.root, args.rules_dir or "rules"))
    t0 = time.time()
    res = detection.Engine(rules, events).run()
    alerts = res["alerts"]
    intel = enrich.Intel(p(args.root, "intel/threat_intel.yaml"))
    alerts = enrich.enrich_alerts(alerts, settings, intel)
    for a in alerts:
        # batch-run detection lag: how far behind the newest event in the alert the pipeline ran.
        a["detection_latency_s"] = max(0, int((session_start - dt.datetime.fromisoformat(
            a["last_seen"])).total_seconds()))
    dest = p(args.root, settings["paths"]["alerts"])
    write_jsonl(dest, alerts)
    secs = time.time() - t0
    print(f"[+] {len(alerts)} alerts from {len(events)} events in {secs:.2f}s "
          f"({len(res['rules_fired'])}/{res['rules_total']} rules fired, "
          f"{len(events)/secs:,.0f} events/s)")
    for a in sorted(alerts, key=lambda x: -x["score"])[:25]:
        print(f"    {a['score']:3d} {a['severity'].upper():9s} {a['rule_id']:17s} "
              f"{a['rule_name'][:52]:52s} x{a['count']}")
    print(f"    ... full list in {os.path.relpath(dest, args.root)}")
    return 0


def cmd_cases(args):
    settings, _ = _load_events(args, events_required=False)
    alerts = read_jsonl(p(args.root, settings["paths"]["alerts"]))
    if not alerts:
        print("[!] no alerts found - run `soc.py detect` first")
        return 1
    alerts = cases_mod.dedup_alerts(alerts, minutes=10)
    t0 = time.time()
    cases = cases_mod.build_cases(alerts, settings)
    actions = cases_mod.run_playbooks(cases, settings)
    for c in cases:
        c["session_start"] = dt.datetime.now(dt.timezone.utc).isoformat()
    for c in cases:
        c.pop("_alerts", None)
    write_json(p(args.root, settings["paths"]["cases"]), cases)
    print(f"[+] {len(cases)} incidents from {len(alerts)} deduped alerts in {time.time()-t0:.2f}s; "
          f"{actions} simulated response actions")
    for c in sorted(cases, key=lambda x: -x["score"]):
        print(f"    {c['case_id']} {c['recommended_priority']} {c['status']:9s} "
              f"{c['score']:3d} | {c['alert_count']:2d} alerts | {c['title'][:58]}")
    return 0


def cmd_stats(args):
    settings, _ = _load_events(args, events_required=False)
    alerts = read_jsonl(p(args.root, settings["paths"]["alerts"]))
    rules = detection.load_rules(p(args.root, args.rules_dir or "rules"))
    fired = {a["rule_id"] for a in alerts}
    covered = {t for a in alerts for t in a.get("technique", [])}
    print(f"rules total {len(rules)} | fired {len(fired)} | never fired "
          f"{len([r for r in rules if r.id not in fired])}")
    print(f"MITRE techniques covered by firing rules: {len(covered)}")
    if not alerts:
        print("[!] no alerts on disk yet - build the dataset first:  python soc.py run")
        return 0
    print("\nfalse-positive candidates (low score, or intel says legit tooling):")
    for a in sorted(alerts, key=lambda x: x["score"])[:6]:
        print(f"    {a['score']:3d} {a['rule_id']:17s} {a['rule_name'][:56]}")
    return 0


def cmd_report(args):
    settings, events = _load_events(args, events_required=False)
    alerts = read_jsonl(p(args.root, settings["paths"]["alerts"]))
    cases = json.load(open(p(args.root, settings["paths"]["cases"]))) \
        if os.path.exists(p(args.root, settings["paths"]["cases"])) else []
    ing = json.load(open(p(args.root, "data/processed/ingest_stats.json"))) \
        if os.path.exists(p(args.root, "data/processed/ingest_stats.json")) else {}
    out = report_mod.write(args.root, settings, alerts, cases, ing)
    print(f"[+] report written: {out}")
    return 0


def cmd_run(args):
    print("=" * 78)
    print(" SOC-PROJECT - full pipeline  " + dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 78)
    # --no-gen keeps whatever the operator appended to data/telemetry; the
    # dashboard's refresh button needs that, or it deletes the evidence it
    # was pressed to reveal
    stages = (cmd_ingest, cmd_rules, cmd_detect, cmd_cases)
    if not getattr(args, "no_gen", False):
        stages = (cmd_gen,) + stages
    for fn in stages:
        print("-" * 78)
        rc = fn(args)
        if rc:
            return rc
    print("-" * 78)
    cmd_stats(args)
    cmd_report(args)
    print("-" * 78)
    print("[+] done. Next: python soc.py serve --port 8080   (live triage dashboard)")
    return 0


def cmd_live(args):
    """Continuously re-run ingest -> detect -> cases as the log files grow (poor man's streaming).

    Real SOC: tail the log shipper's output. Demo: append lines to data/telemetry/* and watch
    alerts appear on the dashboard every N seconds.
    """
    print(f"[*] live mode: sweeping telemetry every {args.every}s "
          f"{'for ' + str(args.runs) + ' cycles' if args.runs else '(Ctrl-C to stop)'}")
    # seed the baseline from whatever is already on disk, otherwise the first
    # cycle reports the whole alert count as if it had just arrived
    try:
        prev = len(read_jsonl(p(args.root, load_settings(
            p(args.root, args.config))["paths"]["alerts"])))
    except (OSError, ValueError, KeyError):
        prev = 0
    cycle = 0
    while True:
        cycle += 1
        try:
            cmd_ingest(args)
            cmd_detect(args)
            cmd_cases(args)
            n = len(read_jsonl(p(args.root, load_settings(p(args.root, args.config))
                                 ["paths"]["alerts"])))
            if n != prev:
                print(f"[+] cycle {cycle}: {n} alerts ({n - prev:+d}) - dashboard refreshed")
                prev = n
            if args.runs and cycle >= args.runs:
                return 0
        except KeyboardInterrupt:  # pragma: no cover
            print("\n[+] stopped")
            return 0
        time.sleep(args.every)


def cmd_serve(args):
    from soc import dashboard
    dashboard.serve(args.root, host=args.host, port=args.port)
    return 0


def cmd_demo(args):
    from soc.demo import walkthrough
    return walkthrough(args.root)


def _load_events(args, events_required=True):
    settings = load_settings(p(args.root, args.config))
    path = p(args.root, settings["paths"]["events"])
    if not os.path.exists(path):
        if events_required:
            raise SystemExit("[!] no normalized events - run `soc.py ingest` first")
        return settings, []
    return settings, read_jsonl(path)


# ------------------------------------------------------------------ CLI
def build_parser():
    ap = argparse.ArgumentParser(prog="soc.py", description="SOC-PROJECT - a working SOC in Python")
    ap.add_argument("--root", default=ROOT, help="project root (default: repo dir)")
    ap.add_argument("--config", default="config/settings.yaml")
    ap.add_argument("--rules-dir", default=None, help="override rules directory")
    # options any stage may need, so `run` can hand its namespace to every stage
    ap.add_argument("--events", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--hours", type=int, default=4)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--no-gen", action="store_true", default=False,
                    help="refresh what is on disk instead of regenerating telemetry")
    # The same flags, accepted *after* the subcommand too ("gen --events 300").
    # SUPPRESS matters: without it the subparser would overwrite a value already
    # parsed at top level ("--events 300 gen") back to its own default.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=argparse.SUPPRESS, help="project root")
    common.add_argument("--config", default=argparse.SUPPRESS)
    common.add_argument("--rules-dir", default=argparse.SUPPRESS)
    common.add_argument("--events", type=int, default=argparse.SUPPRESS,
                        help="benign noise events per source")
    common.add_argument("--seed", type=int, default=argparse.SUPPRESS)
    common.add_argument("--hours", type=int, default=argparse.SUPPRESS)
    common.add_argument("--host", default=argparse.SUPPRESS)
    common.add_argument("--port", type=int, default=argparse.SUPPRESS)
    common.add_argument("--no-gen", action="store_true", default=argparse.SUPPRESS,
                        help="skip telemetry regeneration (refresh what is on disk)")

    def stage(name, help_, fn):
        sp = sub.add_parser(name, help=help_, parents=[common])
        sp.set_defaults(fn=fn)
        return sp

    sub = ap.add_subparsers(dest="cmd", required=True)
    stage("gen", "generate synthetic telemetry", cmd_gen)
    stage("ingest", "parse + normalize raw logs", cmd_ingest)
    stage("rules", "validate + list detection rules", cmd_rules)
    stage("detect", "run detections -> alerts", cmd_detect)
    stage("cases", "correlate -> incidents -> playbook response", cmd_cases)
    stage("stats", "coverage / tuning report", cmd_stats)
    stage("report", "write REPORT.md", cmd_report)
    stage("run", "everything, in order", cmd_run)
    lv = sub.add_parser("live", help="re-run the pipeline as telemetry grows", parents=[common])
    lv.add_argument("--every", type=float, default=5.0)
    lv.add_argument("--runs", type=int, default=0, help="stop after N cycles (0 = forever)")
    lv.set_defaults(fn=cmd_live)
    stage("serve", "live dashboard", cmd_serve)
    stage("demo", "narrated incident walkthrough", cmd_demo)
    return ap


if __name__ == "__main__":
    args = build_parser().parse_args()
    _require_project()
    try:
        rc = args.fn(args)
    except ValueError as exc:
        # rule authoring / config / half-written data mistakes are actionable, not internal
        # faults: show the message (which names file, line and fix) and exit non-zero
        sys.stderr.write(str(exc) + "\n")
        if os.environ.get("SOC_DEBUG"):
            traceback.print_exc()
        else:
            sys.stderr.write("    (set SOC_DEBUG=1 to see the full traceback)\n")
        sys.exit(2)
    sys.exit(rc or 0)
