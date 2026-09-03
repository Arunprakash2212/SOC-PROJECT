"""Pipeline tests. Run: python -m unittest discover -s tests -v

These exercise the real modules (no re-implementation): parsing -> detection -> enrichment ->
correlation -> response -> dashboard/report. The important assertions are the *negative* ones:
a detection engine that fires on everything is worthless, so benign input must produce no alerts.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

from soc import cases as cases_mod  # noqa: E402
from soc import dashboard, detection, enrich, parsers, report  # noqa: E402
from soc.event_schema import ensure_schema  # noqa: E402
from soc.geo import is_private  # noqa: E402

RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
with open(os.path.join(os.path.dirname(RULES), "config", "settings.yaml"),
      encoding="utf-8") as _fh:
    SETTINGS = yaml.safe_load(_fh)


def E(**kw):
    """Build a normalized event the way the pipeline would."""
    ts = kw.pop("ts", "2026-09-02T03:20:00+00:00")
    ev = ensure_schema({"@timestamp": ts, **kw})
    return ev


def load(rules_subset=None):
    rules = detection.load_rules(RULES)
    return [r for r in rules if (rules_subset is None or r.id in rules_subset)]


def detect(events, subset=None):
    rules = load(subset)
    res = detection.Engine(rules, events).run()
    intel = enrich.Intel(os.path.join(os.path.dirname(RULES), "intel", "threat_intel.yaml"))
    return enrich.enrich_alerts(res["alerts"], SETTINGS, intel), res


def _load_cli():
    """soc.py is a script, not a module - load it the way the shell does."""
    import importlib.util
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location("soc_cli", os.path.join(root, "soc.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CliFlags(unittest.TestCase):
    """Shared options must work on either side of the subcommand."""

    def parser(self):
        return _load_cli().build_parser()

    def test_flags_are_accepted_before_or_after_the_stage(self):
        ap = self.parser()
        a = ap.parse_args(["--events", "300", "gen"])
        b = ap.parse_args(["gen", "--events", "300"])
        self.assertEqual(a.events, 300)
        self.assertEqual(b.events, 300)

    def test_a_value_given_after_the_stage_still_reaches_run(self):
        ap = self.parser()
        a = ap.parse_args(["run", "--events", "1500", "--hours", "2"])
        self.assertEqual((a.events, a.hours), (1500, 2))
        self.assertEqual(ap.parse_args(["run"]).events, 8000)      # defaults intact

    def test_serve_still_takes_its_own_port(self):
        self.assertEqual(self.parser().parse_args(["serve", "--port", "9999"]).port, 9999)


class RefreshWithoutRegen(unittest.TestCase):
    """The dashboard's refresh button must not delete the telemetry it reads."""

    def test_no_gen_flag_is_accepted_on_either_side(self):
        ap = _load_cli().build_parser()
        self.assertTrue(ap.parse_args(["run", "--no-gen"]).no_gen)
        self.assertTrue(ap.parse_args(["--no-gen", "run"]).no_gen)
        self.assertFalse(ap.parse_args(["run"]).no_gen)

    def test_run_skips_the_gen_stage_only_when_asked(self):
        cli = _load_cli()
        seen = []
        real = {n: getattr(cli, n) for n in
                ("cmd_gen", "cmd_ingest", "cmd_rules", "cmd_detect", "cmd_cases", "cmd_stats",
                 "cmd_report")}
        for name in real:
            setattr(cli, name, (lambda nm: (lambda *a, **k: seen.append(nm) or 0))(name))
        import contextlib, io
        try:
            for flag in (True, False):
                seen.clear()
                with contextlib.redirect_stdout(io.StringIO()):   # cmd_run prints stage banners
                    cli.cmd_run(type("A", (), {"no_gen": flag, "root": "."})())
                if flag:
                    self.assertNotIn("cmd_gen", seen)
                    self.assertIn("cmd_ingest", seen)
                else:
                    self.assertEqual(seen[0], "cmd_gen")
        finally:
            for name, fn in real.items():
                setattr(cli, name, fn)

    def test_dashboard_rerun_uses_the_non_destructive_path(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "soc", "dashboard.py"), encoding="utf-8").read()
        self.assertIn('"soc.py", "run", "--no-gen"', src)


class HalfWrittenOutput(unittest.TestCase):
    """A cut-off data file must say which file, how much is usable, and the fix."""

    def test_truncated_records_are_named_not_raw_json_noise(self):
        cli = _load_cli()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "events.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"a": 1}) + "\n")
                fh.write('{"b": "unterminated')
            with self.assertRaises(ValueError) as cm:
                cli.read_jsonl(path)
            msg = str(cm.exception)
        self.assertIn("events.jsonl", msg)
        self.assertIn("line 2", msg)
        self.assertIn("1 complete record", msg)
        self.assertIn("soc.py run", msg)
        self.assertNotIn("Traceback", msg)

    def test_space_guard_rejects_a_volume_that_cannot_hold_the_dataset(self):
        cli = _load_cli()
        real = cli.shutil.disk_usage
        cli.shutil.disk_usage = lambda p: type("U", (), {"free": 4 * 1024 * 1024})()
        try:
            with self.assertRaises(ValueError) as cm:
                cli._space_guard(".")
        finally:
            cli.shutil.disk_usage = real
        self.assertIn("not enough free space", str(cm.exception))

    def test_space_guard_is_quiet_when_the_volume_has_room(self):
        cli = _load_cli()
        with tempfile.TemporaryDirectory() as d:
            self.assertGreater(cli._space_guard(d), 30 * 1024 * 1024)

    def test_write_failure_names_the_file_and_the_bytes_landed(self):
        cli = _load_cli()
        real = cli.os.fsync
        cli.os.fsync = lambda fd: (_ for _ in ()).throw(OSError(28, "No space left on device"))
        try:
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError) as cm:
                    cli.write_jsonl(os.path.join(d, "alerts.jsonl"), [{"x": i} for i in range(500)])
        finally:
            cli.os.fsync = real
        msg = str(cm.exception)
        self.assertIn("could not finish writing alerts.jsonl", msg)
        self.assertIn("No space left on device", msg)


class TitleClipping(unittest.TestCase):
    """Case titles break on word boundaries - a half word reads as corruption."""

    def test_long_text_is_cut_at_a_word_boundary(self):
        self.assertEqual(cases_mod._clip("Brute-force authentication attempts from 3 hosts", 24),
                         "Brute-force")
        self.assertEqual(cases_mod._clip("Repeated web-mail authentication failures", 12), "Repeated")

    def test_dotted_tokens_are_never_left_partially_truncated(self):
        # an IP or domain is a single token: trimming inside it invents an address
        keep = "Vertical port scan against the perimeter - 198.51.100.23"
        self.assertEqual(cases_mod._clip(keep, 60), keep)          # short enough: untouched
        self.assertEqual(cases_mod._clip(keep, 50), "Vertical port scan against the perimeter")
        self.assertEqual(cases_mod._clip("scan against the perimeter - 198.51.100.23", 38),
                         "scan against the perimeter")
        self.assertEqual(cases_mod._clip("198.51.100.23", 11), "198.51")   # no half octet

    def test_campaign_titles_stay_inside_the_dashboard_slot(self):
        group = [{"rule_name": f"Rule number {i} - noise"} for i in range(5)]
        title = cases_mod._title(group, {})
        self.assertTrue(title.startswith("Campaign: "))
        self.assertLessEqual(len(title), 58)
        self.assertIn("+ 4 related", title)


class Parsers(unittest.TestCase):
    def test_apache_line_normalizes(self):
        evs = parsers.parse_apache(
            ['203.0.113.44 - m.kumar [02/Sep/2026:08:50:01 +0530] "POST /owa/auth.owa '
             'HTTP/1.1" 401 900 "-" "curl/8.5.0"'])
        e = evs[0]
        self.assertEqual(e["source.ip"], "203.0.113.44")
        self.assertEqual(e["http.response.status_code"], 401)
        self.assertEqual(e["url.path"], "/owa/auth.owa")
        self.assertEqual(e["user.name"], "m.kumar")
        self.assertTrue(e["@timestamp"].startswith("2026-09-02T03:20:01"))

    def test_syslog_keyvalue_and_aliasing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "auth.log")
            with open(path, "w") as fh:
                fh.write("Sep  2 09:00:01 linux-prod-01 sshd[42]: action=authentication-failure "
                         "outcome=failure user=root ip=45.155.205.10 rport=51222 method=password\n")
                fh.write("garbage that is not a syslog line at all\n")
            evs, st = parsers.read_source(path, SETTINGS["sources"]["ssh"])
        self.assertEqual(len(evs), 1)
        self.assertEqual(st["parse_errors"], 1, "malformed lines must be counted, not swallowed")
        e = evs[0]
        self.assertEqual(e["event.dataset"], "auth")
        self.assertEqual(e["event.action"], "authentication-failure")
        self.assertEqual(e["source.ip"], "45.155.205.10")
        self.assertTrue(e["logon.failure"])

    def test_sysmon_eventid_aliasing(self):
        raw = {"@timestamp": "2026-09-02T03:20:00+00:00", "event.dataset": "process_creation",
               "EventID": 1, "Computer": "WS-1", "User": "m.kumar",
               "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
               "CommandLine": "powershell.exe -enc AAAA"}
        ev = parsers.apply_aliases(ensure_schema(dict(raw)), "Sysmon")
        self.assertEqual(ev["process.name"], "powershell.exe")
        self.assertEqual(ev["process.parent"], "outlook.exe")
        self.assertEqual(ev["host.name"], "WS-1")
        self.assertIn("process-create", ev["tags"])

    def test_is_private_rejects_testnet_false_friend(self):
        self.assertTrue(is_private("10.10.31.27"))
        self.assertTrue(is_private("192.168.1.5"))
        # Python's own ipaddress.is_private calls TEST-NET ranges private; a SOC that trusts it
        # never alerts on attacker IPs in documentation space.
        self.assertFalse(is_private("203.0.113.44"))
        self.assertFalse(is_private("198.51.100.23"))


class Matchers(unittest.TestCase):
    def test_list_membership_both_directions(self):
        ev = E(**{"event.action": ["failed-logon"], "tags": ["sysmon/1"]})
        self.assertTrue(detection._match_clause("event.action", ["deny", "failed-logon"], ev))
        self.assertFalse(detection._match_clause("event.action", ["allow"], ev))
        self.assertTrue(detection._match_clause("tags", ["sysmon/1"], ev))

    def test_operators(self):
        ev = E(**{"network.bytes": 5000, "url.path": "/a/b", "source.ip": "1.2.3.4"})
        self.assertTrue(detection._match_clause("network.bytes", {"gte": 2500}, ev))
        self.assertFalse(detection._match_clause("network.bytes", {"gt": 5000}, ev))
        self.assertTrue(detection._match_clause("url.path", {"wildcard": "/a/*"}, ev))
        self.assertTrue(detection._match_clause("url.path", {"regex": "^/a/"}, ev))
        self.assertTrue(detection._match_clause("missing.field", {"exists": False}, ev))
        self.assertTrue(detection._match_clause("source.ip", {"cidr": ["1.0.0.0/8"]}, ev))


class Detection(unittest.TestCase):
    def test_brute_force_fires_and_benign_stays_quiet(self):
        evs = [E(**{"event.dataset": "authentication", "event.action": "failed-logon",
                    "event.outcome": "failure", "source.ip": "203.0.113.44",
                    "source.ip_not_private": True, "user.name": "someone",
                    "ts": f"2026-09-02T03:{i // 4:02d}:{(i * 3) % 60:02d}+00:00"})
               for i in range(40)]
        alerts, _ = detect(evs, {"SOC-BRUTE-001"})
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], 40)
        # same rule, 5 failures only -> must NOT alert
        alerts2, _ = detect(evs[:5], {"SOC-BRUTE-001"})
        self.assertEqual(alerts2, [], "threshold rule fired below its own threshold")

    def test_filter_suppresses_known_scanner(self):
        # 14 distinct ports in 40s = one vertical scan inside a single 5-minute bucket
        evs = [E(**{"event.dataset": "firewall", "event.action": "deny",
                    "source.ip": "203.0.113.77", "destination.port": 80 + i,
                    "destination.ip": "10.10.20.30",
                    "ts": f"2026-09-02T03:00:{i * 3:02d}+00:00"}) for i in range(14)]
        alerts, _ = detect(evs, {"SOC-SCAN-020"})
        self.assertEqual(alerts, [], "the licensed-scanner filter is not working")
        evs2 = [dict(e, **{"source.ip": "198.51.100.23"}) for e in evs]
        alerts2, _ = detect(evs2, {"SOC-SCAN-020"})
        self.assertEqual(len(alerts2), 1)
        self.assertGreaterEqual(alerts2[0].get("distinct_count", 0), 10)
        # the same 14 ports spread over ~1 h never fill a 5-minute bucket: no alert
        slow = [E(**{"event.dataset": "firewall", "event.action": "deny",
                     "source.ip": "198.51.100.23", "destination.port": 80 + i,
                     "destination.ip": "10.10.20.30",
                     "ts": f"2026-09-02T03:{i * 4:02d}:00+00:00"}) for i in range(14)]
        alerts3, _ = detect(slow, {"SOC-SCAN-020"})
        self.assertEqual(alerts3, [], "scan rule must respect its tumbling window")

    def test_beaconing_cov_detects_regular_polling(self):
        evs = [E(**{"event.dataset": "proxy", "network.direction": "outbound",
                    "process.name": "svcmon.exe", "source.ip": "10.10.31.27",
                    "destination.domain": "new-domain-today.example",
                    "user.name": "m.kumar", "host.name": "WS-1",
                    "ts": (dt.datetime(2026, 9, 2, 3, 0, tzinfo=dt.timezone.utc) +
                           dt.timedelta(seconds=i * 47)).isoformat()})
               for i in range(40)]
        alerts, _ = detect(evs, {"SOC-C2-023"})
        self.assertEqual(len(alerts), 1, "regular 47s beacon over 31 min must be found")
        self.assertLess(alerts[0]["baseline"]["cov"], 0.08)
        # jittery human browsing to a *different* asset (own group) -> must not fire
        import random
        rnd = random.Random(7)
        noisy = [E(**{"event.dataset": "proxy", "network.direction": "outbound",
                      "process.name": "svcmon.exe", "source.ip": "10.10.31.99",
                      "destination.domain": "some-shopping-site.example",
                      "user.name": "s.devi", "host.name": "WS-HR-03",
                      "ts": (dt.datetime(2026, 9, 2, 3, tzinfo=dt.timezone.utc) +
                             dt.timedelta(seconds=sorted(rnd.uniform(0, 1750)
                                                           for _ in range(40))[i])).isoformat()})
                 for i in range(40)]
        alerts2, _ = detect(noisy, {"SOC-C2-023"})
        self.assertEqual(alerts2, [], "beaconing rule fired on random human intervals")

    def test_exclude_process_allowlist(self):
        evs = [dict(e, **{"process.name": "chrome.exe"}) for e in
               [E(**{"event.dataset": "proxy", "network.direction": "outbound",
                     "process.name": "chrome.exe", "source.ip": "10.10.31.27",
                     "destination.domain": "outlook.office365.com", "user.name": "s.devi",
                     "host.name": "WS-HR-03",
                     "ts": (dt.datetime(2026, 9, 2, 3, tzinfo=dt.timezone.utc) +
                            dt.timedelta(seconds=i * 47)).isoformat()}) for i in range(40)]]
        alerts, _ = detect(evs, {"SOC-C2-023"})
        self.assertEqual(alerts, [], "allow-listed process should never raise a beaconing alert")

    def test_sequence_requires_prior_events(self):
        base = {"event.dataset": "authentication", "source.ip": "203.0.113.44",
                "source.ip_not_private": True, "user.name": "m.kumar", "host.name": "WS-1"}
        prior = [E(**{**base, "event.action": "failed-logon", "event.outcome": "failure",
                      "ts": f"2026-09-02T03:{i:02d}:00+00:00"}) for i in range(12)]
        # 03:15 is inside the 30-minute sequence window for every failure above
        succ = E(**{**base, "event.action": "successful-logon", "event.outcome": "success",
                    "ts": "2026-09-02T03:15:00+00:00"})
        alerts, _ = detect(prior + [succ], {"SOC-LOGIN-003"})
        self.assertEqual(len(alerts), 1)
        self.assertGreaterEqual(alerts[0]["prior_events"], 10)
        # success with no failures beforehand -> no alert
        alerts2, _ = detect([succ], {"SOC-LOGIN-003"})
        self.assertEqual(alerts2, [], "sequence rule must require the prior condition")
        # a success 3 hours later must NOT inherit the morning's failures (window expired)
        late = dict(succ, **{"@timestamp": "2026-09-02T06:15:00+00:00"})
        late.pop("_ts", None)
        alerts3, _ = detect(prior + [late], {"SOC-LOGIN-003"})
        self.assertEqual(alerts3, [], "sequence window is not being enforced")

    def test_impossible_travel(self):
        from soc.geo import locate
        a = locate("103.216.220.14")["coords"]
        b = locate("104.28.55.10")["coords"]
        self.assertGreater(detection.haversine_km(a, b), 400)
        evs = [E(**{"event.dataset": "authentication", "event.action": "successful-logon",
                     "source.ip": "103.216.220.14", "source.ip_not_private": True,
                     "user.name": "a.priya", "ts": "2026-09-02T03:00:00+00:00"}),
               E(**{"event.dataset": "authentication", "event.action": "successful-logon",
                    "source.ip": "104.28.55.10", "source.ip_not_private": True,
                    "user.name": "a.priya", "ts": "2026-09-02T03:25:00+00:00"})]
        alerts, _ = detect(evs, {"SOC-IMPTVL-005"})
        self.assertEqual(len(alerts), 1)
        self.assertGreater(alerts[0]["geo"]["distance_km"], 400)

    def test_duplicate_rule_ids_are_named_and_actionable(self):
        """The failure a stale draft in rules/ causes must say which two files collide."""
        import shutil
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(RULES, os.path.join(d, "rules"))
            with open(os.path.join(d, "rules", "99_stale_draft.yaml"), "w") as fh:
                yaml.dump([{"id": "SOC-BRUTE-001", "name": "old draft",
                            "logsource": {"dataset": ["authentication"]},
                            "condition": [{"event.outcome": "failure"}]}], fh)
            with self.assertRaises(ValueError) as ctx:
                detection.load_rules(os.path.join(d, "rules"))
            msg = str(ctx.exception)
            self.assertIn("SOC-BRUTE-001", msg)
            self.assertIn("99_stale_draft.yaml", msg, "must name the offending file")
            self.assertIn("01_authentication.yaml", msg, "must name what it collides with")
            self.assertIn("delete", msg.lower(), "must tell the reader what to do")

    def test_template_named_files_are_never_loaded(self):
        """`_template.yaml` can lose its underscore copying through chat/wiki/zip - so match the
        name too, otherwise a broken sample file stops a real pipeline for no reason."""
        import shutil
        with tempfile.TemporaryDirectory() as d:
            rdir = os.path.join(d, "rules")
            shutil.copytree(RULES, rdir)
            for name in ("template.yaml", "_template.yaml", "sample_draft.yaml", "00_notes.md"):
                with open(os.path.join(rdir, name), "w") as fh:
                    fh.write("- id: X\n  condition:\n    - url.path: {regex: >-\n      bad}\n")
            self.assertEqual([r.id for r in detection.load_rules(rdir)],
                             [r.id for r in detection.load_rules(RULES)])

    def test_bad_rule_file_reports_location_and_fix(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            rdir = os.path.join(d, "rules")
            shutil.copytree(RULES, rdir)
            bad = os.path.join(rdir, "05_broken.yaml")
            with open(bad, "w") as fh:
                fh.write("- id: SOC-BROKEN-900\n  name: bad\n  condition:\n"
                         "    - url.path: {regex: >-\n        /evil}\n")
            with self.assertRaises(ValueError) as ctx:
                detection.load_rules(rdir)
            msg = str(ctx.exception)
            self.assertIn("05_broken.yaml", msg)
            self.assertIn("line 4", msg, "must point at the offending line")
            self.assertIn("flow mapping", msg, "must name the likely cause")
            self.assertIn("regex:", msg, "must show the fix")

    def test_rules_all_parse_and_regexes_compile(self):
        rules = load()
        self.assertGreaterEqual(len(rules), 25)
        seen = set()
        for r in rules:
            self.assertNotIn(r.id, seen, f"duplicate rule id {r.id}")
            seen.add(r.id)
            self.assertTrue(r.name and r.tactic, f"{r.id} missing name/tactic")
            self.assertIsInstance(r.technique, list)

            def walk(x):
                if isinstance(x, dict):
                    for k, v in x.items():
                        if k == "regex":
                            __import__("re").compile(v)
                        walk(v)
                elif isinstance(x, list):
                    for i in x:
                        walk(i)
            walk(r.conditions)
            walk(r.filters)


class Enrichment(unittest.TestCase):
    def test_entities_host_intel_and_score(self):
        alerts = [{"rule_id": "SOC-C2-022", "rule_name": "x", "severity": "critical",
                   "confidence": "high", "risk": 88, "tactic": "command-and-control",
                   "technique": ["T1071"], "count": 3, "first_seen": "2026-09-02T03:02:36+00:00",
                   "last_seen": "2026-09-02T03:02:36+00:00",
                   "entities": {"source.ip": "10.10.31.27", "destination.domain":
                                "cdn-update-service.net", "process.name": "svcmon.exe",
                                "user.name": "m.kumar"}, "note": "", "sample": []}]
        enrich.enrich_alerts(alerts, SETTINGS, enrich.Intel(
            os.path.join(os.path.dirname(RULES), "intel", "threat_intel.yaml")))
        a = alerts[0]
        self.assertEqual(a["entities"]["host.name"], "WS-FINANCE-07",
                         "asset inventory should resolve the host from the workstation IP")
        self.assertTrue(any(h["category"] == "c2" for h in a["enrichment"]["intel"]))
        self.assertGreaterEqual(a["score"], 80)
        self.assertIn(a["triage_suggested"], ("escalate", "investigate"))
        self.assertTrue(a["score_reasons"])

    def test_playbook_safety_guards(self):
        case = {"case_id": "INC-1", "entities": {"user.name": "SYSTEM", "source.ip":
                "10.10.31.27", "host.name": "WS-1"}, "score": 99, "status": "new",
                "severity": "critical", "_alerts": [{"severity": "critical", "confidence": "high",
                "tactic": "credential-access", "rule_id": "SOC-CRED-013"}]}
        cases_mod.run_playbooks([case], SETTINGS)
        res = {r["action"]: r["result"] for r in case["response"]}
        self.assertIn("block_ip_at_waf", res)
        self.assertIn("SKIPPED", res["block_ip_at_waf"],
                      "must not auto-block an internal IP found on the wire")
        self.assertIn("SKIPPED", res["disable_account"],
                      "must not disable a built-in identity like SYSTEM")


class Cases(unittest.TestCase):
    def _alerts(self):
        return [
            {"rule_id": "SOC-BRUTE-001", "rule_name": "brute", "severity": "high",
             "confidence": "high", "risk": 70, "score": 84, "tactic": "credential-access",
             "technique": ["T1110"], "count": 219, "repeat_count": 1,
             "first_seen": "2026-09-02T02:50:00+00:00", "last_seen": "2026-09-02T02:59:59+00:00",
             "entities": {"source.ip": "203.0.113.44", "user.name": "m.kumar",
                          "host.name": "WS-FINANCE-07"}, "note": "", "sample": [],
             "alert_id": "a1"},
            {"rule_id": "SOC-PSH-010", "rule_name": "powershell", "severity": "high",
             "confidence": "high", "risk": 80, "score": 57, "tactic": "execution",
             "technique": ["T1059.001"], "count": 1, "repeat_count": 1,
             "first_seen": "2026-09-02T03:02:15+00:00", "last_seen": "2026-09-02T03:02:15+00:00",
             "entities": {"user.name": "m.kumar", "host.name": "WS-FINANCE-07",
                          "process.name": "powershell.exe"}, "note": "", "sample": [],
             "alert_id": "a2"},
            {"rule_id": "SOC-SCAN-020", "rule_name": "scan", "severity": "medium",
             "confidence": "high", "risk": 45, "score": 63, "tactic": "reconnaissance",
             "technique": ["T1595.001"], "count": 48, "repeat_count": 1,
             "first_seen": "2026-09-02T03:15:00+00:00", "last_seen": "2026-09-02T03:20:00+00:00",
             "entities": {"source.ip": "198.51.100.23", "destination.ip": "10.10.20.30"},
             "note": "", "sample": [], "alert_id": "a3"},
        ]

    def test_dedup_and_correlation(self):
        a = self._alerts()
        dup = dict(a[0], repeat_count=1, count=5, first_seen="2026-09-02T03:40:00+00:00",
                   last_seen="2026-09-02T03:41:00+00:00", alert_id="a1b")
        deduped = cases_mod.dedup_alerts(a + [dup], minutes=60)
        self.assertEqual(len(deduped), 3, "same rule + same entity must collapse")
        self.assertTrue(any(d.get("deduped_from") for d in deduped))
        groups = cases_mod.correlate(deduped, window_minutes=90, min_shared=1)
        merged = [g for g in groups if len(g) > 1]
        self.assertEqual(len(merged), 1)
        ids = {x["rule_id"] for x in merged[0]}
        self.assertEqual(ids, {"SOC-BRUTE-001", "SOC-PSH-010"},
                         "endpoint alerts share the host; the scanner has no host so it stays apart")
        # far-in-time identical alert must not merge
        far = dict(a[0], first_seen="2026-09-02T09:00:00+00:00", last_seen="2026-09-02T09:01:00+00:00",
                   alert_id="a1z")
        g2 = cases_mod.correlate([a[0], far], window_minutes=90)
        self.assertEqual(len(g2), 2, "correlation must respect the time window")

    def test_case_build_playbook_and_metrics(self):
        cases = cases_mod.build_cases(self._alerts(), SETTINGS)
        self.assertEqual(len(cases), 2)
        top = max(cases, key=lambda c: c["score"])
        self.assertEqual(top["severity"], "high")
        self.assertIn("T1059.001", top["techniques"])
        chain = top["narrative"]["chain"]
        self.assertLessEqual(chain.find("execution"), chain.find("credential-access"),
                             "kill chain must be ordered by the attack sequence, not by score")
        n = cases_mod.run_playbooks(cases, SETTINGS)
        self.assertGreater(n, 0)
        self.assertTrue(all(c["status"] in ("contained", "new", "closed") for c in cases))
        m = cases_mod.compute_metrics(cases, 10000, 2.0,
                                      {"coverage": None, "rules_fired": 3, "rules_total": 5,
                                       "unfired_rules": ["SOC-X"]}, {"lines": 10000})
        self.assertEqual(m["cases"], 2)
        self.assertEqual(m["rules_fired"], 3)
        self.assertEqual(m["detection_gap_pct"], 20.0)

    def test_triage_journal_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "data/processed"))
            alerts = self._alerts()
            cases = cases_mod.build_cases(alerts, SETTINGS)
            for c in cases:
                c.pop("_alerts", None)
            with open(os.path.join(d, "data/processed/cases.json"), "w") as fh:
                json.dump(cases, fh)
            with open(os.path.join(d, "data/processed/alerts.jsonl"), "w") as fh:
                for a in alerts:
                    fh.write(json.dumps(a) + "\n")
            with open(os.path.join(d, "data/processed/ingest_stats.json"), "w") as fh:
                json.dump({"events": 3, "seconds": 0.1, "sources": {"auth": {"lines": 3,
                         "parsed": 3, "parse_errors": 0}}}, fh)
            view = dashboard.build_view(d)
            self.assertEqual(view["metrics"]["cases"], len(cases))
            with open(os.path.join(d, "data/processed/triage_state.jsonl"), "a") as fh:
                fh.write(json.dumps({"case_id": cases[0]["case_id"], "status": "false-positive",
                                      "note": "approved activity"}) + "\n")
            view2 = dashboard.build_view(d)
            self.assertEqual(view2["metrics"]["fp_count"], 1)
            self.assertEqual(view2["triage_count"], 1)
            closed = [c for c in view2["cases"] if c["case_id"] == cases[0]["case_id"]][0]
            self.assertEqual(closed["status"], "closed")
            self.assertTrue(closed.get("closed_at"))
            self.assertTrue(view2["metrics"]["mttr_s"] is None or view2["metrics"]["mttr_s"] >= 0)
            csv_body = dashboard.alerts_csv(view2)
            self.assertEqual(csv_body.count("\n"), len(alerts) + 1)
            self.assertIn("case_id", csv_body.splitlines()[0])


class TriageJournalInReport(unittest.TestCase):
    """Analyst decisions must reach REPORT.md, not live only in the dashboard view."""

    @staticmethod
    def _line(case_id, status, note):
        return json.dumps({"case_id": case_id, "status": status, "note": note,
                           "assignee": "analyst.onshift",
                           "decided_at": "2026-09-03T06:11:04+00:00"}) + "\n"

    @staticmethod
    def _journal(d, lines):
        jdir = os.path.join(d, "data", "processed")
        os.makedirs(jdir, exist_ok=True)
        with open(os.path.join(jdir, "triage_state.jsonl"), "w", encoding="utf-8") as fh:
            fh.writelines(lines)

    @staticmethod
    def _correlated_cases():
        alerts = [{"rule_id": "SOC-BRUTE-001", "rule_name": "brute", "severity": "high",
                   "confidence": "high", "risk": 70, "score": 84, "tactic": "credential-access",
                   "technique": ["T1110"], "count": 3,
                   "first_seen": "2026-09-02T02:50:00+00:00",
                   "last_seen": "2026-09-02T02:59:59+00:00",
                   "entities": {"source.ip": "203.0.113.44"}, "sample": [],
                   "score_reasons": ["x"], "note": ""}]
        cs = cases_mod.build_cases(alerts, SETTINGS)
        cases_mod.run_playbooks(cs, SETTINGS)
        for c in cs:
            c.pop("_alerts", None)
        return cs

    def test_last_decision_per_case_wins_and_junk_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            cid = "INC-TEST-001"
            self._journal(d, [self._line(cid, "false-positive", "first call"),
                              "this line is not json at all\n",
                              self._line(cid, "contained", "revised by the shift lead"),
                              self._line("INC-TEST-002", "false-positive", "licensed scanner")])
            latest = cases_mod.read_triage_journal(d)
            self.assertEqual(len(latest), 2, "one entry per case id, the last one wins")
            self.assertEqual(latest[cid]["status"], "contained")
            self.assertEqual(latest[cid]["note"], "revised by the shift lead")
            self.assertNotIn("first call", json.dumps(latest))

    def test_decisions_are_rendered_in_the_report(self):
        cs = self._correlated_cases()
        with tempfile.TemporaryDirectory() as d:
            self._journal(d, [self._line(cs[0]["case_id"], "contained", "revised by the shift lead"),
                              self._line("INC-OTHER-001", "false-positive", "licensed scanner")])
            out = report.write(d, SETTINGS, [], cs,
                              {"events": 10, "seconds": 0.1, "sources": {}})
            with open(out, encoding="utf-8") as fh:
                body = fh.read()
        self.assertIn("What the analyst actually decided in this run", body)
        self.assertIn("| Analyst decisions recorded | 2 |", body)
        self.assertIn("revised by the shift lead", body)
        self.assertIn("**1** marked false positive", body)
        self.assertIn("**Analyst decision:** `contained`", body)
        self.assertNotIn("not json at all", body, "a junk journal line leaked into the report")

    def test_no_journal_says_so_instead_of_silently_omitting_the_section(self):
        cs = self._correlated_cases()
        with tempfile.TemporaryDirectory() as d:
            out = report.write(d, SETTINGS, [], cs, {"events": 10, "seconds": 0.1, "sources": {}})
            with open(out, encoding="utf-8") as fh:
                body = fh.read()
        self.assertIn("No analyst decisions recorded for this dataset", body)
        self.assertIn("| Analyst decisions recorded | 0 |", body)


class Report(unittest.TestCase):
    def test_report_is_written_and_populated(self):
        with tempfile.TemporaryDirectory() as d:
            alerts = [{"rule_id": "SOC-BRUTE-001", "rule_name": "brute", "severity": "high",
                       "confidence": "high", "risk": 70, "score": 84, "tactic": "credential-access",
                       "technique": ["T1110"], "count": 219,
                       "first_seen": "2026-09-02T02:50:00+00:00",
                       "last_seen": "2026-09-02T02:59:59+00:00",
                       "entities": {"source.ip": "203.0.113.44"}, "sample": [],
                       "score_reasons": ["x"], "note": ""}]
            cases = cases_mod.build_cases(alerts, SETTINGS)
            cases_mod.run_playbooks(cases, SETTINGS)
            for c in cases:
                c.pop("_alerts", None)
            out = report.write(d, SETTINGS, alerts, cases,
                              {"events": 1000, "seconds": 0.2,
                               "sources": {"auth": {"lines": 1000, "parsed": 1000,
                                                    "parse_errors": 0}}})
            with open(out, encoding="utf-8") as fh:
                body = fh.read()
            self.assertTrue(os.path.exists(out))
            for section in ("Shift summary", "Detection results", "Incidents",
                            "Coverage and tuning", "Limitations"):
                self.assertIn(section, body)
            self.assertIn("SOC-BRUTE-001", body)
            self.assertNotIn("{'", body, "python dict repr leaked into the markdown")


class EndToEnd(unittest.TestCase):
    """Full run on a tiny dataset: proves the shipped rules match the shipped telemetry."""

    @classmethod
    def setUpClass(cls):
        from soc import telemetry
        cls.tmp = tempfile.mkdtemp()
        telemetry.generate(os.path.join(cls.tmp, "telemetry"), events=400, seed=1337, hours=4)
        td = os.path.join(cls.tmp, "telemetry")
        cls.events, cls.stats = [], {"lines": 0, "parsed": 0, "parse_errors": 0}
        for name, spec in SETTINGS["sources"].items():
            path = os.path.join(td, spec["file"])
            if os.path.exists(path):
                evs, st = parsers.read_source(path, spec)
                cls.events += evs
                for k in ("lines", "parsed", "parse_errors"):
                    cls.stats[k] += st[k]
        cls.events.sort(key=lambda e: e.get("@timestamp") or "")
        cls.alerts, _ = detect(cls.events)
        cls.deduped = cases_mod.dedup_alerts(cls.alerts, minutes=10)
        cls.cases = cases_mod.build_cases(cls.deduped, SETTINGS)
        cases_mod.run_playbooks(cls.cases, SETTINGS)

    def test_pipeline_end_to_end(self):
        self.assertGreater(len(self.events), 1500)
        self.assertEqual(self.stats["parse_errors"], 0)
        fired = {a["rule_id"] for a in self.alerts}
        for expected in ("SOC-BRUTE-001", "SOC-LOGIN-003", "SOC-PSH-010", "SOC-C2-023",
                         "SOC-CRED-013", "SOC-EVADE-014", "SOC-RANSOM-030", "SOC-EXFIL-024",
                         "SOC-DNSTUN-027", "SOC-IMPTVL-005"):
            self.assertIn(expected, fired, f"attack-chain rule {expected} did not fire")
        self.assertLess(len(self.cases), len(self.alerts), "correlation must compress the queue")
        self.assertGreater(max(c["alert_count"] for c in self.cases), 5,
                           "one incident should hold the whole intrusion chain")
        top = max(self.cases, key=lambda c: c["score"])
        self.assertIn("command-and-control", top["narrative"]["chain"])
        self.assertTrue(any(r["action"] == "isolate_host" for r in top["response"]))

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
