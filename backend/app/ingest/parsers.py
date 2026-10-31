"""Log parsers: convert raw lines into canonical events while preserving evidence.

Supported formats (auto-detected per line):
  - syslog (OpenSSH/sshd, sudo, openvpn style)
  - JSONL EDR / structured events

Every returned event carries the ORIGINAL raw line (`raw`) for evidence.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

SSH_FAILED = re.compile(r"Failed\s+(?:password|publickey|keyboard-interactive\S*)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d.a-fA-F:]+)")
SSH_ACCEPTED = re.compile(r"Accepted\s+(?:password|publickey|keyboard-interactive\S*)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.a-fA-F:]+)")
PAM_SESSION = re.compile(r"pam_unix\(sshd:session\): session opened for user (?P<user>\S+)")
SUDO_RE = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<attempts>\d+\s+incorrect password attempts\s*;)?\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<tuser>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$")
OPENVPN_OK = re.compile(r"user\s+(?P<user>[^/]+)/\S+:\s*authentication succeeded from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?")
OPENVPN_FAIL = re.compile(r"user\s+(?P<user>[^/]+)/\S+:\s*(?:TLS handshake failed|authentication failed) from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def parse_syslog_timestamp(mon: str, day: int, time_text: str, now: datetime) -> float | None:
    month = MONTHS.get(mon)
    if not month:
        return None
    try:
        hh, mm, ss = (int(x) for x in time_text.split(":"))
        # syslog has no year: use current year, but if that lands in the future by
        # more than a day, assume previous year (Dec logs read in January).
        year = now.year
        dt = datetime(year, month, day, hh, mm, ss)
        if (dt - now).total_seconds() > 86400:
            dt = dt.replace(year=year - 1)
        return dt.timestamp()
    except (ValueError, OverflowError):
        return None


def _ev(**kw: Any) -> dict[str, Any]:
    kw.setdefault("event_type", "other")
    kw.setdefault("severity", "info")
    kw.setdefault("outcome", "unknown")
    # every canonical column must exist (None if absent) for batch SQL inserts
    for f in ("ts", "ts_text", "username", "src_ip", "dst_ip", "host", "process",
              "action", "message", "details"):
        kw.setdefault(f, None)
    if kw.get("details") is not None and not isinstance(kw["details"], dict):
        kw["details"] = {"value": kw["details"]}
    return kw


def _norm_user(user: str | None) -> str | None:
    """Normalize account names: strip 'DOMAIN\\' / 'HOST\\' prefixes so the same
    account correlates across log sources (e.g. 'WEB-01\\svc-backup' == 'svc-backup')."""
    if not user:
        return user
    u = str(user).strip()
    if "\\" in u:
        u = u.split("\\")[-1]
    return u or None


def parse_syslog_line(line: str, now: datetime) -> dict[str, Any] | None:
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    ts = parse_syslog_timestamp(m["mon"], int(m["day"]), m["time"], now)
    host, tag, msg, pid = m["host"], m["tag"].strip(), m["msg"].strip(), m["pid"]
    base = {"host": host, "process": tag, "ts": ts, "ts_text": f'{m["mon"]} {m["day"]} {m["time"]}'}

    if tag == "sshd":
        fm = SSH_FAILED.search(msg)
        am = SSH_ACCEPTED.search(msg)
        if fm:
            return _ev(event_type="auth_failure", severity="low", outcome="failure",
                       username=_norm_user(fm["user"]), src_ip=fm["ip"], action="ssh_login",
                       message=msg, **base)
        if am:
            return _ev(event_type="auth_success", severity="info", outcome="success",
                       username=_norm_user(am["user"]), src_ip=am["ip"], action="ssh_login",
                       message=msg, **base)
        ps = PAM_SESSION.search(msg)
        if ps:
            return _ev(event_type="auth_success", severity="info", outcome="success",
                       username=_norm_user(ps["user"]), action="session_open", message=msg, **base)
        return _ev(event_type="other", message=msg, **base)

    if tag == "sudo":
        sm = SUDO_RE.match(msg)
        if sm:
            failed = bool(sm["attempts"])
            return _ev(
                event_type="privilege", severity="high" if failed else "info",
                outcome="failure" if failed else "success",
                username=sm["user"], action="sudo",
                message=msg,
                details={"target_user": sm["tuser"], "command": sm["cmd"].strip(),
                         "failed_attempts": failed},
                **base)
        return _ev(event_type="privilege", message=msg, **base)

    if tag == "openvpn":
        om = OPENVPN_OK.search(msg)
        ofm = OPENVPN_FAIL.search(msg)
        if om:
            return _ev(event_type="auth_success", severity="info", outcome="success",
                       username=_norm_user(om["user"]), src_ip=om["ip"], action="vpn_login",
                       message=msg, **base)
        if ofm:
            return _ev(event_type="auth_failure", severity="low", outcome="failure",
                       username=_norm_user(ofm["user"]), src_ip=ofm["ip"], action="vpn_login",
                       message=msg, **base)
        return _ev(event_type="other", message=msg, **base)

    return _ev(event_type="other", message=msg, **base)


# Field aliases accepted in JSONL records
FIELD_ALIASES = {
    "timestamp": ["timestamp", "time", "@timestamp", "ts", "datetime", "date"],
    "host": ["host", "hostname", "computer", "computer_name", "device", "host_name"],
    "user": ["user", "username", "account", "account_name", "subject_user_name", "user_name"],
    "src_ip": ["src_ip", "source_ip", "client_ip", "source_address", "ip", "src"],
    "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "target_ip", "remote_ip", "dst"],
    "process": ["process", "process_name", "image", "exe", "binary", "parent_process"],
    "command_line": ["command_line", "cmdline", "command", "cmd"],
    "event_type": ["event", "event_type", "type", "category"],
    "event_id": ["event_id", "eventid", "id"],
    "outcome": ["outcome", "status", "result", "action_result"],
    "port": ["dst_port", "port", "dest_port"],
}


def _pick(rec: dict[str, Any], key: str) -> Any:
    for alias in FIELD_ALIASES[key]:
        if alias in rec and rec[alias] not in (None, ""):
            return rec[alias]
    return None


def _parse_iso_ts(value: Any, now: datetime) -> tuple[float | None, str | None]:
    if value is None:
        return None, None
    text = str(value)
    try:
        # Wall-clock interpretation: 'Z' suffix is dropped so syslog and structured
        # sources line up on the same timeline (both parsed as naive local time).
        t = text.rstrip("Z")
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt.timestamp(), text
    except ValueError:
        return None, text


KNOWN_EVENT_TYPES = {
    "processcreate": "process", "process_create": "process", "process": "process",
    "networkconnect": "network", "network_connect": "network", "network": "network",
    "filecreate": "file", "file_create": "file", "file": "file",
    "logon": "auth_success", "logonfailure": "auth_failure", "auth_success": "auth_success",
    "auth_failure": "auth_failure", "privilege": "privilege",
}

SUSPICIOUS_HINTS = re.compile(
    r"(whoami|ipconfig|nltest|net(\.exe)?\s+(user|group|localgroup|use)|tasklist|quser|query\s+user|"
    r"mimikatz|lsass|procdump|psexec|wmic|powershell.*(-enc|-encodedcommand|downloadstring|iex)|"
    r"certutil|bitsadmin|sudo\s|/etc/shadow|nmap|nc\s+-|ncat|ssh\s+-o|curl\s+-T|wget\s+http)",
    re.IGNORECASE)


def parse_jsonl_line(line: str, now: datetime) -> dict[str, Any] | None:
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict):
        return None

    ts, ts_text = _parse_iso_ts(_pick(rec, "timestamp"), now)
    user = _pick(rec, "user")
    host = _pick(rec, "host")
    process = _pick(rec, "process")
    cmdline = _pick(rec, "command_line")
    raw_type = str(_pick(rec, "event_type") or "").strip().lower()
    event_type = KNOWN_EVENT_TYPES.get(raw_type.replace(" ", ""), raw_type or "other")
    if event_type in ("4688", "4624"):
        event_type = "process"
    if event_type in ("other", "") and cmdline:
        event_type = "process"

    outcome = str(_pick(rec, "outcome") or "unknown").lower()
    if outcome not in ("success", "failure"):
        outcome = "unknown"

    message = str(rec.get("message") or cmdline or raw_type or "structured event")
    suspicious = bool(cmdline and SUSPICIOUS_HINTS.search(cmdline))

    if event_type == "process":
        severity = "high" if suspicious else "info"
    elif event_type == "network":
        severity = "medium" if suspicious else "info"
    else:
        severity = "info"

    details = {k: v for k, v in rec.items()
               if k not in {"timestamp", "time", "@timestamp", "host", "user", "username",
                            "process", "command_line", "cmdline", "event", "message"}
               and not isinstance(v, (dict, list))}
    if cmdline:
        details["command"] = cmdline

    return _ev(event_type=event_type, severity=severity, outcome=outcome,
               username=_norm_user(str(user)) if user else None,
               src_ip=str(_pick(rec, "src_ip")) if _pick(rec, "src_ip") else None,
               dst_ip=str(_pick(rec, "dst_ip")) if _pick(rec, "dst_ip") else None,
               host=str(host) if host else None,
               process=str(process) if process else None,
               action=raw_type or None,
               message=message, details=details, ts=ts, ts_text=ts_text)


def detect_format(line: str) -> str:
    s = line.lstrip()
    if s.startswith("{"):
        try:
            json.loads(s)
            return "jsonl"
        except json.JSONDecodeError:
            pass
    if SYSLOG_RE.match(s):
        return "syslog"
    return "unknown"
