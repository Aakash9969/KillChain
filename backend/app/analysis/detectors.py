"""Deterministic, explainable threat detection rules.

Every rule is a pure function over parsed canonical events. Each detection
carries: why it triggered (explanation), the exact supporting event ids,
MITRE ATT&CK technique ids, and the Cyber Kill Chain stage. No randomness.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta

from . import mitre

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

PRIVATE_IP = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|::1|fc)")


def is_external(ip: str | None) -> bool:
    return bool(ip) and not PRIVATE_IP.match(ip)


def fmt_time(ts: float | None) -> str:
    if ts is None:
        return "?"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


# process/command families -> MITRE technique (id, name), severity floor
PROC_RULES: list[tuple[str, str, str, str]] = [
    (r"whoami", "T1033", "System Owner/User Discovery", "medium"),
    (r"ipconfig|ifconfig", "T1016", "System Network Configuration Discovery", "medium"),
    (r"nltest|net(\.exe)?\s+(user|group|localgroup)", "T1087", "Account Discovery", "high"),
    (r"tasklist|ps\s+aux|quser|query\s+user", "T1057", "Process Discovery", "medium"),
    (r"netstat", "T1049", "System Network Connections Discovery", "medium"),
    (r"cat\s+/etc/(shadow|passwd)", "T1003.008", "/etc/passwd and /etc/shadow", "high"),
    (r"mimikatz|lsass|procdump|sekurlsa", "T1003", "OS Credential Dumping", "critical"),
    (r"psexec|wmic\s+/node|wmiexec|smbexec|impacket", "T1021", "Remote Services", "high"),
    (r"powershell.*(-enc|-e\s|downloadstring|iex\s)|certutil.*urlcache|bitsadmin\s+/transfer", "T1059.001", "PowerShell", "high"),
    (r"nmap|nc\s+-|ncat|test-netconnection|test-netconnection", "T1046", "Network Service Discovery", "high"),
    (r"curl\s+-T|--upload-file|wget\s+--post-file", "T1041", "Exfiltration Over C2 Channel", "critical"),
    (r"mysqldump|pg_dump|sqlite3\s+\S+\s+\.dump", "T1005", "Data from Local System", "high"),
]

REMOTE_PORTS = {22: "SSH", 3389: "RDP", 445: "SMB", 5985: "WinRM", 5986: "WinRM-HTTPS"}


def _det(rule_id: str, title: str, severity: str, explanation: str, confidence: str,
         mitre: list[str], stage: str, events: list[dict], entities: dict) -> dict:
    eids = [e["id"] for e in events]
    tss = [e["ts"] for e in events if e.get("ts") is not None]
    return {
        "rule_id": rule_id, "title": title, "severity": severity, "explanation": explanation,
        "confidence": confidence, "mitre": mitre, "killchain_stage": stage,
        "event_ids": eids, "entities": entities,
        "first_ts": min(tss) if tss else None, "last_ts": max(tss) if tss else None,
    }


def _uniq(entities: dict) -> dict:
    return {k: sorted(set(v)) for k, v in entities.items()}


# ---------------------------------------------------------------------------
# R1: repeated failed logins (brute force) per (user, src_ip)
# ---------------------------------------------------------------------------
def detect_brute_force(events: list[dict]) -> list[dict]:
    from .. import config
    fails = [e for e in events if e["event_type"] == "auth_failure" and e.get("username")]
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in fails:
        groups[(e["username"], e.get("src_ip"))].append(e)

    out = []
    for (user, ip), evs in groups.items():
        evs.sort(key=lambda e: (e["ts"] or 0))
        window = timedelta(minutes=config.BRUTEFORCE_WINDOW_MIN)
        i = 0
        while i < len(evs):
            j = i
            while j < len(evs) and evs[j]["ts"] and evs[i]["ts"] and \
                    evs[j]["ts"] - evs[i]["ts"] <= window.total_seconds():
                j += 1
            burst = evs[i:j]
            if len(burst) >= config.BRUTEFORCE_FAILURE_COUNT:
                hosts = [e.get("host") or "?" for e in burst]
                span = (burst[-1]["ts"] - burst[0]["ts"]) / 60 if burst[-1]["ts"] and burst[0]["ts"] else 0
                sev = "critical" if len(burst) >= 10 else "high"
                out.append(_det(
                    "BRUTE_FORCE_AUTH", "Repeated failed logins (brute force)", sev,
                    f"{len(burst)} failed authentication attempts for account '{user}' from "
                    f"{ip} against {', '.join(sorted(set(hosts)))} within {span:.0f} minutes "
                    f"({fmt_time(burst[0]['ts'])} - {fmt_time(burst[-1]['ts'])}). This rate of failure "
                    f"from a single source is consistent with automated password guessing.",
                    "high" if len(burst) >= 8 else "medium",
                    ["T1110.001", "T1110"], "Delivery", burst,
                    _uniq({"users": [user], "ips": [ip or "?"], "hosts": hosts, "processes": []})))
            i = j if j > i else i + 1
    return out


# ---------------------------------------------------------------------------
# R2: successful login following repeated failures (same user+src_ip)
# ---------------------------------------------------------------------------
def detect_success_after_failures(events: list[dict]) -> list[dict]:
    from .. import config
    auths = [e for e in events if e["event_type"] in ("auth_failure", "auth_success")
             and e.get("username")]
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in auths:
        groups[(e["username"], e.get("src_ip"))].append(e)

    out = []
    for (user, ip), evs in groups.items():
        evs.sort(key=lambda e: (e["ts"] or 0))
        for idx, e in enumerate(evs):
            if e["event_type"] != "auth_success" or e.get("action") == "session_open":
                continue
            window = timedelta(minutes=config.SUCCESS_AFTER_FAILURE_WINDOW_MIN)
            prior = [p for p in evs[:idx]
                     if p["event_type"] == "auth_failure" and p.get("ts") and e.get("ts")
                     and e["ts"] - p["ts"] <= window.total_seconds()]
            if len(prior) >= 3:
                host = e.get("host") or "?"
                out.append(_det(
                    "SUCCESS_AFTER_FAILURES", "Successful login after repeated failures", "critical",
                    f"Account '{user}' successfully authenticated from {ip} to {host} at "
                    f"{fmt_time(e['ts'])} after {len(prior)} failed attempts within the previous "
                    f"{config.SUCCESS_AFTER_FAILURE_WINDOW_MIN} minutes. This is the classic "
                    f"signature of a brute-force attack succeeding - the account should be "
                    f"treated as compromised.",
                    "high",
                    ["T1078", "T1110"], "Exploitation",
                    prior + [e],
                    _uniq({"users": [user], "ips": [ip or "?"], "hosts": [host], "processes": []})))
    # de-dup: one detection per (user, ip, success event)
    seen, final = set(), []
    for d in out:
        key = (d["entities"]["users"][0], tuple(d["entities"]["ips"]), tuple(d["event_ids"]))
        if key not in seen:
            seen.add(key)
            final.append(d)
    return final


# ---------------------------------------------------------------------------
# R3: suspicious authentication activity (odd-hour login from new source)
# ---------------------------------------------------------------------------
def detect_suspicious_auth(events: list[dict]) -> list[dict]:
    from .. import config
    successes = [e for e in events if e["event_type"] == "auth_success"
                 and e.get("username") and e.get("action") in ("ssh_login", "vpn_login")]
    seen_user_ip: dict[tuple, float] = {}
    for e in successes:
        key = (e["username"], e.get("src_ip"))
        if e.get("ts") is not None:
            k = key
            if k not in seen_user_ip:
                seen_user_ip[k] = e["ts"]

    out = []
    for e in successes:
        if e.get("ts") is None:
            continue
        hour = datetime.fromtimestamp(e["ts"]).hour
        odd_hour = hour >= config.ODD_HOUR_START or hour < config.ODD_HOUR_END
        first_seen = seen_user_ip.get((e["username"], e.get("src_ip"))) == e["ts"]
        if odd_hour and first_seen:
            hour_desc = "night hours (22:00-06:00)"
            out.append(_det(
                "SUSPICIOUS_AUTH_ODD_HOUR", "Login outside business hours from a first-seen source", "medium",
                f"Account '{e['username']}' authenticated to {e.get('host') or '?'} from "
                f"{e.get('src_ip') or '?'} at {fmt_time(e['ts'])} - during {hour_desc} - and this "
                f"source IP had never been observed for this account before in the analyzed data.",
                "medium",
                ["T1078.001", "T1078"], "Exploitation", [e],
                _uniq({"users": [e["username"]], "ips": [e.get("src_ip") or "?"],
                       "hosts": [e.get("host") or "?"], "processes": []})))
    return out


# ---------------------------------------------------------------------------
# R4: suspicious process execution (EDR)
# ---------------------------------------------------------------------------
def detect_suspicious_processes(events: list[dict]) -> list[dict]:
    procs = [e for e in events if e["event_type"] == "process"]
    flagged: dict[tuple, list[dict]] = defaultdict(list)  # (host,user) -> events
    matched_mitre: dict[tuple, set] = defaultdict(set)
    matched_cmds: dict[tuple, list[str]] = defaultdict(list)

    for e in procs:
        cmd = (e.get("message") or "") + " " + str((e.get("details") or {}).get("command", ""))
        for pattern, tid, name, sev in PROC_RULES:
            if re.search(pattern, cmd, re.IGNORECASE):
                key = (e.get("host") or "?", e.get("username") or "?")
                flagged[key].append(e)
                matched_mitre[key].add((tid, name))
                matched_cmds[key].append(cmd.strip())
                break

    out = []
    for (host, user), evs in flagged.items():
        evs.sort(key=lambda e: (e["ts"] or 0))
        mitre = sorted(matched_mitre[(host, user)])
        tids = [m[0] for m in mitre]
        # severity: highest floor among matched command families
        sev_rank = 0
        for pattern, tid, name, floor in PROC_RULES:
            if any(tid == m[0] for m in mitre):
                sev_rank = max(sev_rank, SEV_RANK[floor])
        severity = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}[sev_rank]
        cmd_list = sorted(set(matched_cmds[(host, user)]))[:6]
        out.append(_det(
            "SUSPICIOUS_PROCESS_EXEC", "Suspicious process execution / discovery activity", severity,
            f"EDR telemetry recorded {len(evs)} suspicious process execution(s) on {host} run by "
            f"{user} ({fmt_time(evs[0]['ts'])} - {fmt_time(evs[-1]['ts'])}). Matched commands: "
            f"{'; '.join(repr(c) for c in cmd_list)}. These commands are characteristic of "
            f"post-compromise reconnaissance and credential access tooling.",
            "high",
            tids, "Installation", evs,
            _uniq({"users": [user], "ips": [e.get("src_ip") for e in evs if e.get("src_ip")],
                   "hosts": [host], "processes": sorted({e.get("process") or "?" for e in evs})})))
    return out


# ---------------------------------------------------------------------------
# R5: remote access / lateral movement between hosts
#
# Deliberately context-aware: normal workstation -> server logins are everyday
# operations. We only raise a detection when the remote authentication is
# connected to other suspicious evidence:
#   * the account is a suspected-compromised account (external brute force), or
#   * the source host recently ran suspicious discovery tooling, or
#   * the source host itself was accessed from an external IP.
# ---------------------------------------------------------------------------
def _suspicious_context(events: list[dict]) -> tuple[set, set, set]:
    compromised_accounts: set[str] = set()
    for e in events:
        if e["event_type"] == "auth_failure" and e.get("username") and is_external(e.get("src_ip")):
            compromised_accounts.add(e["username"])
    suspicious_hosts: set[str] = set()
    for e in events:
        if e["event_type"] == "process" and e.get("host"):
            cmd = (e.get("message") or "") + " " + str((e.get("details") or {}).get("command", ""))
            if any(re.search(p, cmd, re.IGNORECASE) for p, _, _, _ in PROC_RULES):
                suspicious_hosts.add(e["host"])
    ext_accessed_hosts: set[str] = set()
    for e in events:
        if e["event_type"] == "auth_success" and is_external(e.get("src_ip")) and e.get("host"):
            ext_accessed_hosts.add(e["host"])
    return compromised_accounts, suspicious_hosts, ext_accessed_hosts


def detect_lateral_movement(events: list[dict]) -> list[dict]:
    compromised, suspicious_hosts, ext_hosts = _suspicious_context(events)
    auths = [e for e in events if e["event_type"] == "auth_success"
             and e.get("src_ip") and e.get("host") and e.get("action") == "ssh_login"
             and not is_external(e["src_ip"])]
    conns = [e for e in events if e["event_type"] == "network" and e.get("src_ip")
             and e.get("dst_ip") and e.get("host")]

    out = []
    for e in auths:
        src_ip, dst_host, user = e["src_ip"], e["host"], e["username"]
        carrier = [c for c in conns
                   if c.get("dst_ip") and c["dst_ip"] and c.get("src_ip") == src_ip
                   and c.get("host") != dst_host
                   and c.get("ts") and e.get("ts") and 0 <= (e["ts"] - c["ts"]) <= 180]
        src_host = carrier[-1]["host"] if carrier else src_ip
        reasons = []
        if user in compromised:
            reasons.append(f"account '{user}' was targeted by external brute-force activity")
        if src_host in suspicious_hosts:
            reasons.append(f"source host {src_host} recently ran suspicious discovery tooling")
        if src_host in ext_hosts:
            reasons.append(f"source host {src_host} was itself accessed from an external IP")
        if not reasons:
            continue  # routine internal login - not lateral movement evidence

        evs = carrier + [e]
        proto = REMOTE_PORTS.get((carrier[-1].get("details") or {}).get("dst_port") if carrier else None, "SSH")
        out.append(_det(
            "LATERAL_MOVEMENT", "Lateral movement between internal hosts", "critical",
            f"Account '{user}' authenticated from internal host {src_host} ({src_ip}) to "
            f"{dst_host} at {fmt_time(e['ts'])} over {proto}. This is flagged as lateral movement "
            f"because {', '.join(reasons)}. Combined with the observed remote connection this is "
            f"evidence of attacker pivoting inside the environment.",
            "high", ["T1021.004", "T1021"], "Installation", evs,
            _uniq({"users": [user], "ips": [src_ip],
                   "hosts": [src_host, dst_host], "processes": ["sshd"]})))

    # internal network probes (recon sweep) - lower severity, own rule
    probes: dict[tuple, list[dict]] = defaultdict(list)
    for c in conns:
        d = c.get("details") or {}
        if d.get("action") == "network_probe" or (c.get("outcome") == "failure" and c.get("dst_ip")):
            probes[(c["host"], c.get("username") or "?", c["dst_ip"])].append(c)
    for (host, user, dst), evs in probes.items():
        if len(evs) < 2:
            continue
        out.append(_det(
            "NETWORK_PROBE_INTERNAL", "Internal network scanning / reachability probing", "medium",
            f"{len(evs)} network probe connection(s) from {host} (user {user}) toward {dst} "
            f"({fmt_time(evs[0]['ts'])} - {fmt_time(evs[-1]['ts'])}). Scanning of neighboring "
            f"internal systems is typical attacker behavior to find the next pivot target.",
            "medium", ["T1046"], "Reconnaissance", evs,
            _uniq({"users": [user], "ips": [evs[0].get("src_ip") or "?"], "hosts": [host, dst],
                   "processes": sorted({e.get("process") or "?" for e in evs})})))
    return out


# ---------------------------------------------------------------------------
# R6: privilege-related suspicious activity
# ---------------------------------------------------------------------------
def detect_privilege_activity(events: list[dict]) -> list[dict]:
    privs = [e for e in events if e["event_type"] == "privilege"]
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in privs:
        d = e.get("details") or {}
        if d.get("failed_attempts"):
            groups[(e.get("username") or "?", e.get("host") or "?")].append(e)

    out = []
    for (user, host), evs in groups.items():
        evs.sort(key=lambda e: (e["ts"] or 0))
        if len(evs) >= 2:
            cmds = sorted({(e.get("details") or {}).get("command", "?") for e in evs})
            out.append(_det(
                "PRIVILEGE_ESCALATION_ATTEMPT", "Failed privilege escalation (sudo) attempts", "high",
                f"Account '{user}' made {len(evs)} failed attempts to elevate privileges via sudo "
                f"on {host} ({fmt_time(evs[0]['ts'])} - {fmt_time(evs[-1]['ts'])}), targeting "
                f"'{(evs[0].get('details') or {}).get('target_user', 'root')}'. Repeated sudo "
                f"failures by a service account indicate an attempt to reach root - a step that "
                f"has no legitimate operational reason at this stage.",
                "high", ["T1548.003", "T1078.003"], "Installation", evs,
                _uniq({"users": [user], "ips": [e.get("src_ip") or "?" for e in evs if e.get("src_ip")],
                       "hosts": [host], "processes": ["sudo"]})))
    return out


# ---------------------------------------------------------------------------
# R7: data staging / exfiltration to external infrastructure
# ---------------------------------------------------------------------------
def detect_exfiltration(events: list[dict]) -> list[dict]:
    out = []
    procs = [e for e in events if e["event_type"] in ("process", "network")]
    for e in procs:
        cmd = str((e.get("details") or {}).get("command", ""))
        m = re.search(r"(curl\s+-T|--upload-file|wget\s+--post-file)", cmd, re.IGNORECASE)
        if not m:
            continue
        dst = e.get("dst_ip")
        # fallback: extract the target host from a URL in the command line
        if not dst:
            um = re.search(r"https?://([\d.a-fA-F:\[\]]+)", cmd)
            if um:
                dst = um.group(1)
        if is_external(dst):
            out.append(_det(
                "EXFIL_EXTERNAL", "Data staged and uploaded to external infrastructure", "critical",
                f"Process '{e.get('process')}' on {e.get('host') or '?'} run by "
                f"{e.get('username') or '?'} transferred a file to external IP "
                f"{dst} at {fmt_time(e['ts'])} (command: {cmd}). Outbound uploads "
                f"to non-corporate infrastructure from a database host indicate data "
                f"exfiltration.",
                "high", ["T1041", "T1567"], "Actions on Objectives", [e],
                _uniq({"users": [e.get("username") or "?"], "ips": [dst],
                       "hosts": [e.get("host") or "?"], "processes": [e.get("process") or "?"]})))
    return out


# ---------------------------------------------------------------------------
# R8: EDR pre-tagged alerts (vendor detections present in the telemetry)
# ---------------------------------------------------------------------------
def detect_edr_tagged_alerts(events: list[dict]) -> list[dict]:
    alerts = [e for e in events if (e.get("details") or {}).get("edr_rule")]
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in alerts:
        d = e.get("details") or {}
        groups[(d["edr_rule"], e.get("host") or "?")].append(e)

    out = []
    for (rule, host), evs in groups.items():
        evs.sort(key=lambda e: (e["ts"] or 0))
        # chain into clusters (same rule + host within 30 min)
        cluster = [evs[0]]
        clusters = []
        for e in evs[1:]:
            if e.get("ts") and cluster[-1].get("ts") and e["ts"] - cluster[-1]["ts"] <= 1800:
                cluster.append(e)
            else:
                clusters.append(cluster)
                cluster = [e]
        clusters.append(cluster)

        for cl in clusters:
            d0 = cl[0].get("details") or {}
            tids = sorted({t for e in cl for t in (e.get("details") or {}).get("edr_mitre", [])})
            tactic = d0.get("edr_tactic") or ""
            stage = mitre.TACTIC_TO_KILLCHAIN.get(tactic.strip(), "Installation")
            extra = {k: v for k, v in d0.items()
                     if k.endswith("_5min") or k.endswith("_60s") or k.startswith("failed_count")}
            ctx = (f" EDR-reported context: {extra}." if extra else "")
            sev = max((e["severity"] for e in cl), key=lambda s: SEV_RANK.get(s, 0))
            out.append(_det(
                "EDR_TAGGED_ALERT", f"EDR alert: {rule}", sev,
                f"The EDR product raised rule '{rule}'{f' (tactic: {tactic})' if tactic else ''} on "
                f"{host} ({len(cl)} event(s), {fmt_time(cl[0]['ts'])} - {fmt_time(cl[-1]['ts'])})."
                f"{ctx} KillChain independently verified these raw events exist in the ingested "
                f"telemetry and correlates them with surrounding activity.",
                "medium", tids, stage, cl,
                _uniq({"users": [e.get("username") or "?" for e in cl],
                       "ips": [ip for e in cl for ip in (e.get("src_ip"), e.get("dst_ip")) if ip],
                       "hosts": [host],
                       "processes": sorted({e.get("process") or "?" for e in cl})})))
    return out


ALL_RULES = [
    detect_brute_force,
    detect_success_after_failures,
    detect_suspicious_auth,
    detect_suspicious_processes,
    detect_lateral_movement,
    detect_privilege_activity,
    detect_exfiltration,
    detect_edr_tagged_alerts,
]


def run_all_detectors(events: list[dict]) -> list[dict]:
    detections: list[dict] = []
    for rule in ALL_RULES:
        detections.extend(rule(events))
    detections.sort(key=lambda d: (-(SEV_RANK.get(d["severity"], 0)), d["first_ts"] or 0))
    return detections
