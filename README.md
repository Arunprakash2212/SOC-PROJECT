# SOC-PROJECT â€” A Working Security Operations Center Pipeline (Pure Python)

A complete, runnable SOC pipeline: **telemetry ingestion â†’ log normalization â†’ Sigma-style
detection rules â†’ entity enrichment with threat intel â†’ incident correlation â†’ automated
playbook response â†’ live triage dashboard â†’ report & metrics.**

No cloud services, no heavy installs. Just Python 3.10+ and PyYAML.

```
 telemetry (synthetic)          normalization              detection                response
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ auth (Sysmon-ish)  â”‚   â”‚                      â”‚   â”‚ 29 Sigma-style    â”‚   â”‚ correlation â†’     â”‚
â”‚ web  (Apache comb.)â”‚â”€â”€â–¶â”‚  parsers per source  â”‚â”€â”€â–¶â”‚ rules + baseline  â”‚â”€â”€â–¶â”‚ cases / incidents â”‚
â”‚ fw   (CSV)         â”‚   â”‚  â†’ one normalized    â”‚   â”‚ beaconing (CoV)   â”‚   â”‚ playbooks (block, â”‚
â”‚ dns  (TSV)         â”‚   â”‚    event schema      â”‚   â”‚ enrichment (IP,   â”‚   â”‚ disable, isolate) â”‚
â”‚ proc (JSONL)       â”‚   â”‚  + parse-error count â”‚   â”‚ user, host, geo)  â”‚   â”‚ MTTD / MTTR       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                                                                     â”‚
                                                                          â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                                                                          â”‚ live dashboard      â”‚
                                                                          â”‚ triage, ATT&CK cov.,â”‚
                                                                          â”‚ timeline, CSV exportâ”‚
                                                                          â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## 5-hour build plan (the timetable this project was built to)

| Time | Task | Done when |
|---|---|---|
| 0:00â€“0:30 | Scaffold: package layout, event schema (`soc/event_schema.py`), config loader | `python soc.py rules` lists rules |
| 0:30â€“1:30 | Telemetry generator (`soc/telemetry.py`) â€” 7 sources, realistic benign noise + a full attack chain | `data/telemetry/*` non-empty, ~8k events |
| 1:30â€“2:15 | Parsers + normalizer (`soc/parsers.py`), tolerant of malformed lines | `ingest` loads every source into one schema |
| 2:15â€“3:15 | Detection engine (`soc/detection.py`): selectors, filters, thresholds (grouped + distinct), aggregation windows | `detect` fires the expected alerts, low FP |
| 3:15â€“3:45 | Enrichment (`soc/enrich.py`): private-IP/RDNS-lite geo, threat-intel match, user risk, host criticality | alerts carry entities + score |
| 3:45â€“4:15 | Correlation â†’ incidents, scoring, dedup, playbooks (`soc/cases.py`) | incidents with TTP chains + response actions |
| 4:15â€“4:45 | Live dashboard (`soc/dashboard.py`) + `report` (REPORT.md, metrics, ATT&CK coverage) | `soc.py run` then `serve` works |
| 4:45â€“5:00 | Tests (`tests/test_soc.py`), README, viva prep | `python -m unittest discover tests` green |

Everything in this repo is inside that plan â€” nothing here needs more than 5 hours of your time to
rebuild or extend.

## Run it

```bash
cd SOC-PROJECT
pip install pyyaml            # the only dependency

python soc.py run                 # regenerate telemetry + full pipeline (one command, the demo)
python soc.py serve --port 8080   # live dashboard: triage incidents, ATT&CK coverage, CSV export
python soc.py demo                # narrated console walkthrough of the incident (good for presenting)
python soc.py report              # writes REPORT.md
python soc.py live --every 5      # re-sweep every 5s; append lines to data/telemetry/* and watch alerts appear
python -m unittest discover -s tests -v   # 39 tests, all stages
```

Verified on the committed dataset: **10,443 normalized events â†’ 29 alerts (24/29 rules fired) â†’
7 incidents â†’ 16 simulated response actions**, ingest 1.6 s, detection 0.6 s (~18k events/s), 0
parse errors.

`serve` and `live` keep running until you press Ctrl+C, so give each its own PowerShell window - the block above is a menu of commands, not one script to paste. If you are already inside the project folder, drop the first `cd` line.

### Windows / PowerShell notes

PyYAML is the only third-party dependency, and it must be installed into the *same* interpreter you
run the script with. If you see `ModuleNotFoundError: No module named 'yaml'`, do:

```powershell
py -3 -m pip install -r requirements.txt      # py launcher â†’ the Windows-installed Python
# or, if pip reports "externally-managed-environment" (Microsoft Store / new installers):
cd SOC-PROJECT
py -3 -m venv .venv ; .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

`python -m pip` (not bare `pip`) matters on Windows: several Pythons are often installed and plain
`pip` may write into a different one than the one running `soc.py`. The CLI now prints that advice
itself instead of a traceback if the dependency is missing. Other Windows-specific care already
taken: all files are read/written with `encoding="utf-8"` (so rules containing em-dashes never hit
a cp1252 decode error), stdout is reconfigured to UTF-8 with `errors="replace"` so no `print`
crashes on a legacy console, and the raw-text parsers strip `\r` so CRLF log files
(Notepad / `git checkout` on Windows) parse exactly like LF ones.

Individual stages, if you want to inspect each step (this is what a real SOC shift looks like):

```bash
python soc.py gen   --events 8000 --seed 1337   # synthetic multi-source telemetry into data/telemetry/
python soc.py ingest                            # parse + normalize -> data/processed/events.jsonl
python soc.py rules                             # validate/list detection rules
python soc.py detect                            # run rules + baseline beaconing -> alerts.jsonl
python soc.py cases                             # dedup, correlate, score, run playbooks -> cases.json
python soc.py stats                             # coverage + tuning (which rules never fired, etc.)
```

## What you can show in the viva (defensible talking points)

1. **Ingestion / normalization.** Four raw log formats (Sysmon-style JSON, Apache combined,
   CSV, TSV) are parsed into *one* normalized event schema (a trimmed ECS). Show
   `data/processed/events.jsonl` and point out the `parser_errors` counter â€” a real SOC always
   reports ingestion loss, because silent parsing failure = blind spots.
2. **Detection engineering.** Rules live in YAML, Sigma-style: `selection` (OR of AND-groups),
   `filter` (deny-list to kill false positives), `detection` (threshold / distinct / time
   window), `technique` for MITRE ATT&CK mapping. Add a rule in 10 seconds, see it fire â€”
   do this live: it is the most impressive 30 seconds of the whole demo.
3. **Behavioral detection, not just signatures.** `beaconing.yaml` computes the coefficient of
   variation of inter-arrival times per (process, destination host) â€” no IOC list needed, it
   catches C2 even with a fresh domain. That is the difference between a rule-matching script
   and an actual SOC.
4. **Enrichment & scoring.** Every alert carries entities (user risk, host criticality, IP
   threat-intel category + confidence, geo) and the alert score is a weighted sum
   (`soc/enrich.py`). Same alert on a domain controller scores higher than on a kiosk â€” that
   is how you justify priority to a manager.
5. **Correlation â†’ incidents.** Alerts for one account/IP/host within a time window are stitched
   into one incident with a TTP narrative (recon â†’ credential access â†’ C2 â†’ exfil â†’ impact).
   Without this you drown in 40 alerts; with it you work 4 cases.
6. **Automated response.** Playbooks (from `config/settings.yaml`) run containment actions â€”
   block IP at WAF, disable + force password reset on the account, isolate host, quarantine
   the persistence artifact. Each action records the exact evidence that justified it.
7. **Metrics.** MTTD (detection â†’ alert) and MTTR (alert â†’ case closed), FP rate from triage,
   ATT&CK technique coverage (`soc.py stats` prints rules that never fired â€” tuning is part of
   SOC work).

## Layout

```
SOC-PROJECT/
â”œâ”€â”€ soc.py                 CLI entry point (gen | ingest | rules | detect | cases | stats | report | run | demo | serve)
â”œâ”€â”€ config/settings.yaml   paths, scoring weights, case thresholds, playbooks, severity map
â”œâ”€â”€ rules/*.yaml           29 Sigma-style detection rules (+ rules/_template.yaml to extend)
â”œâ”€â”€ intel/threat_intel.yaml small offline threat-intel feed (IPs, domains, categories)
â”œâ”€â”€ soc/
â”‚   â”œâ”€â”€ event_schema.py    normalized event schema + timestamp helpers
â”‚   â”œâ”€â”€ parsers.py         jsonl / apache combined / csv / syslog-kv parsers, fault tolerant
â”‚   â”œâ”€â”€ telemetry.py       synthetic multi-source telemetry with a full attack chain
â”‚   â”œâ”€â”€ detection.py       rule engine: selectors, filters, thresholds, distinct, beaconing CoV
â”‚   â”œâ”€â”€ enrich.py          entity resolution, geo/user/host intel, alert scoring
â”‚   â”œâ”€â”€ cases.py           dedup, correlation, incident scoring, playbook execution
â”‚   â”œâ”€â”€ dashboard.py       dependency-free live triage dashboard (port 8080)
â”‚   â”œâ”€â”€ demo.py            `soc.py demo`: narrated incident walkthrough for presenting
â”‚   â””â”€â”€ geo.py             offline geolocation + RFC1918 test (see the TEST-NET gotcha below)
â”‚   â””â”€â”€ report.py          REPORT.md generator
â”œâ”€â”€ tests/test_soc.py      20 unittests covering every stage, incl. the negative cases
â”‚                          (benign input must produce no alerts, windows must be enforced)
â””â”€â”€ data/                  telemetry/, processed/ (events, alerts, cases, timeline, triage state)
```

## 5-minute live demo script

1. `python soc.py run` â€” talk through each stage banner while it runs (~10 s).
2. `python soc.py serve --port 8080` â€” open `http://localhost:8080`. Point at the KPI row,
   then the 30-minute event/alert histogram: "this is the shift".
3. Click `INC-â€¦-001` â†’ the kill chain line (recon â†’ initial access â†’ execution â†’ C2 â†’ exfil â†’
   impact) and the **automated response table with justifications**. Say: *"one case, 22 alerts"*.
4. Tab **Alert queue** â†’ scroll to the *Score transparency* table: exactly why an alert scored 100
   vs 38. Then tab **ATT&CK & rules**: 5 idle rules are listed â€” that is tuning, not a bug.
5. Press **False positive** on the OWA alert, type a note â†’ status flips to closed, `fp_count`
   moves, and the decision is appended to `data/processed/triage_state.jsonl`.
6. `cp data/telemetry/auth_windows.jsonl /tmp/x && printf 'not-a-log-line\n' >> data/telemetry/auth_windows.jsonl && python soc.py ingest`
   â†’ the run prints `1 parse error`. Say: *"a SIEM that hides parse failures is a blind spot."*
7. `python soc.py live --every 5` in a second terminal and append a fake brute-force burst:
   new alerts show up on the dashboard within one sweep.

## Extension ideas (pick one if you have more time)

- Swap the JSONL telemetry for a live tail: `soc.py ingest --follow` â†’ same rules, real stream.
- Replace `detection.py`'s scan loop with tumbling windows to argue about late events / watermarks.
- Export alerts as STIX 2.1 bundles, or push them to a ticketing system via the case ID.
- Add a rule for DNS tunneling (bytes-per-query baseline) â€” the telemetry already contains it.
- Tune `min_events`/`max_cov` in `beaconing.yaml` live and show the FP/TP trade-off.

## Honest limitations (say these before your evaluator does)

- Telemetry is synthetic; the parsers and rules are the real artifact, not the data.
- "GeoIP" and "RDNS" are a small static table, not a database; there is no passive DNS.
- "Internal vs external" uses an explicit RFC1918 list, **not** Python's
  `ipaddress.is_private`, because that treats TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24) as private â€” a real trap that silences every "external source" rule. There is a
  unit test pinning this behaviour.
- MTTD/MTTR are computed on the dataset clock (config `correlation.*_lag_minutes`), not the wall
  clock, because the synthetic capture is dated; the raw wall-clock lag is still reported.
- Detections are stateless per run (plus explicit window rules) â€” no long-lived session store,
  so 14-day baselines and true streaming watermarks are out of scope.
- Playbook actions are simulated against a state file (no real EDR/WAF API calls).

**Two launchers, if you prefer not to type the entry-point filename**

```
run.cmd            # whole pipeline, then opens the dashboard on :8080
run.cmd serve      # dashboard only        run.cmd test    # unit tests
run.cmd detect     # any CLI stage or flag is forwarded as-is
```

`run.ps1` is the same thing for PowerShell script fans, but Windows client
machines often default to `ExecutionPolicy Restricted`, which blocks unsigned
`.ps1` files - use `run.cmd`, which has no such restriction.

**If a stage dies with "is corrupt at line N"**

That is a half-written data file, never a bad rule - the pipeline wrote
`data/processed/events.jsonl` (about 18 MB for the default 10,443-event dataset) and the volume could not take it. It
happens on RAM disks, thumb drives, near-full partitions and some `A:`/network
redirectors. The message names the file and how many records survived; the fix
is to move the whole project into a normal folder (Documents is fine) and run
`python soc.py run` again. Before `gen` and before the ingest write the CLI
checks free space and refuses early if the volume has less than 30 MB, and
every write is `fsync`-ed so a full disk fails at the write that filled it
instead of three stages later. Set `SOC_DEBUG=1` to get the full traceback.

