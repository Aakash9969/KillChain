"""SQL-first detectors for very large datasets (FortiGate / firewall scale).

Instead of loading every event into memory, heavy rules are evaluated with
streaming SQL aggregations (GROUP BY / HAVING) and only bounded evidence
samples are materialized. Memory stays O(detections), not O(events).

All rules are deterministic and explainable. Blocked web/IPS/virus events are
reported as observed blocks - they never imply successful compromise.
"""
from __future__ import annotations

import sqlite3

from . import detectors as det_mod
from . import mitre


def _mk(rule_id, title, severity, explanation, confidence, mitre_ids, stage,
        events, entities, extra=None):
    d = det_mod._det(rule_id, title, severity, explanation, confidence, mitre_ids,
                     stage, events, entities)
    if extra:
        d.update(extra)
    return d


def detect_credential_spraying(conn: sqlite3.Connection, min_total=50, min_users=10,
                               max_groups=200) -> list[dict]:
    """Distributed credential attacks: one source IP failing against many accounts."""
    out = []
    rows = conn.execute(
        """SELECT src_ip, COUNT(*) c, COUNT(DISTINCT username) users, MIN(ts) t0, MAX(ts) t1
           FROM events WHERE event_type='auth_failure' AND src_ip IS NOT NULL
           GROUP BY src_ip HAVING c >= ? AND users >= ?
           ORDER BY c DESC LIMIT ?""",
        (min_total, min_users, max_groups)).fetchall()
    for r in rows:
        sample = [dict(x) for x in conn.execute(
            """SELECT id, ts, username, host, src_ip, message FROM events
               WHERE event_type='auth_failure' AND src_ip=? ORDER BY ts LIMIT 40""", (r["src_ip"],))]
        ext = det_mod.is_external(r["src_ip"])
        out.append(_mk(
            "AUTH_SPRAYING", "Distributed credential attack from a single source", "high",
            f"Source {r['src_ip']} produced {r['c']:,} failed authentication attempts against "
            f"{r['users']} distinct accounts (first {det_mod.fmt_time(r['t0'])}, last "
            f"{det_mod.fmt_time(r['t1'])}). This pattern is consistent with automated password "
            f"spraying / brute-forcing from {'external ' if ext else ''}infrastructure. "
            f"Sample of {len(sample)} failures attached; full evidence remains in the Log Explorer.",
            "high" if r["c"] >= 200 else "medium",
            ["T1110.003", "T1110"], "Delivery", sample,
            {"users": sorted({s["username"] or "?" for s in sample})[:30],
             "ips": [r["src_ip"]], "hosts": sorted({s["host"] or "?" for s in sample}),
             "processes": []},
            extra={"aggregate": True, "total_events": r["c"], "distinct_accounts": r["users"]}))
    return out


def detect_pair_bursts(conn: sqlite3.Connection, min_total=30, max_groups=200) -> list[dict]:
    """Classic brute force: many failures for one (account, source) pair.

    Time-window clustering is handled by the full in-memory path; at dataset
    scale a total-count threshold with evidence samples is the pragmatic and
    still deterministic equivalent.
    """
    out = []
    rows = conn.execute(
        """SELECT username, src_ip, COUNT(*) c, MIN(ts) t0, MAX(ts) t1
           FROM events WHERE event_type='auth_failure' AND username IS NOT NULL
           AND src_ip IS NOT NULL
           GROUP BY username, src_ip HAVING c >= ?
           ORDER BY c DESC LIMIT ?""",
        (min_total, max_groups)).fetchall()
    for r in rows:
        sample = [dict(x) for x in conn.execute(
            """SELECT id, ts, username, host, src_ip, message FROM events
               WHERE event_type='auth_failure' AND username=? AND src_ip=?
               ORDER BY ts LIMIT 40""", (r["username"], r["src_ip"]))]
        out.append(_mk(
            "BRUTE_FORCE_AUTH", "Repeated failed logins (brute force)", "high",
            f"{r['c']:,} failed authentication attempts for account '{r['username']}' from "
            f"{r['src_ip']} ({det_mod.fmt_time(r['t0'])} - {det_mod.fmt_time(r['t1'])}). "
            f"This volume from a single source against a single account is consistent with "
            f"automated password guessing. Sample of {len(sample)} failures attached.",
            "high" if r["c"] >= 100 else "medium",
            ["T1110.001", "T1110"], "Delivery", sample,
            {"users": [r["username"]], "ips": [r["src_ip"]],
             "hosts": sorted({s["host"] or "?" for s in sample}), "processes": []},
            extra={"aggregate": True, "total_events": r["c"]}))
    return out


def detect_targeted_bruteforce(conn: sqlite3.Connection, min_total=50, min_ips=5,
                               max_groups=100) -> list[dict]:
    """Targeted brute force: one account attacked from many sources."""
    out = []
    rows = conn.execute(
        """SELECT username, COUNT(*) c, COUNT(DISTINCT src_ip) ips, MIN(ts) t0, MAX(ts) t1
           FROM events WHERE event_type='auth_failure' AND username IS NOT NULL
           GROUP BY username HAVING c >= ? AND ips >= ?
           ORDER BY c DESC LIMIT ?""",
        (min_total, min_ips, max_groups)).fetchall()
    for r in rows:
        sample = [dict(x) for x in conn.execute(
            """SELECT id, ts, username, host, src_ip, message FROM events
               WHERE event_type='auth_failure' AND username=? ORDER BY ts LIMIT 40""",
            (r["username"],))]
        out.append(_mk(
            "AUTH_TARGETED_BRUTE", "Sustained brute force against a specific account", "high",
            f"Account '{r['username']}' received {r['c']:,} failed authentication attempts from "
            f"{r['ips']} distinct source IPs ({det_mod.fmt_time(r['t0'])} - "
            f"{det_mod.fmt_time(r['t1'])}). The account is under targeted credential attack.",
            "high", ["T1110.001", "T1110"], "Delivery", sample,
            {"users": [r["username"]],
             "ips": sorted({s["src_ip"] or "?" for s in sample})[:30],
             "hosts": sorted({s["host"] or "?" for s in sample}), "processes": []},
            extra={"aggregate": True, "total_events": r["c"], "distinct_sources": r["ips"]}))
    return out


def detect_auth_transitions_large(conn: sqlite3.Connection, window_s=3600,
                                  min_failures=3, odd_start=22, odd_end=6) -> list[dict]:
    """Single ordered pass over all authentication events, grouped by
    (username, src_ip): computes success-after-failures and odd-hour
    first-seen logins without per-row queries. Memory is bounded by the
    largest single (account, source) group.
    """
    out = []
    cur = conn.execute(
        """SELECT event_type, ts, id, username, src_ip, host, message
           FROM events
           WHERE event_type IN ('auth_failure', 'auth_success')
             AND username IS NOT NULL AND src_ip IS NOT NULL AND ts IS NOT NULL
           ORDER BY username, src_ip, ts, id""")

    def make_success_det(s, fails, host):
        fails = fails[:100]
        success_ev = {"id": s["id"], "ts": s["ts"], "username": s["username"],
                      "host": s["host"], "src_ip": s["src_ip"], "message": s["message"]}
        return _mk(
            "SUCCESS_AFTER_FAILURES", "Successful login after repeated failures", "critical",
            f"Account '{s['username']}' successfully authenticated to {host} from "
            f"{s['src_ip']} at {det_mod.fmt_time(s['ts'])} after {len(fails)} failed attempts "
            f"from the same source within the previous {window_s // 60} minutes. This is the "
            f"classic signature of a credential attack succeeding - the account should be "
            f"treated as compromised.",
            "high", ["T1078", "T1110"], "Exploitation", fails + [success_ev],
            {"users": [s["username"]], "ips": [s["src_ip"]],
             "hosts": sorted({f.get("host") or "?" for f in fails} | {host or "?"}),
             "processes": []})

    def make_odd_det(s, host):
        ev = {"id": s["id"], "ts": s["ts"], "username": s["username"], "host": host,
              "src_ip": s["src_ip"], "message": s["message"]}
        return _mk(
            "SUSPICIOUS_AUTH_ODD_HOUR",
            "Login outside business hours from a first-seen source", "medium",
            f"Account '{s['username']}' authenticated to {host} from external IP "
            f"{s['src_ip']} at {det_mod.fmt_time(s['ts'])} - during night hours "
            f"({odd_start}:00-{odd_end}:00) - and this IP had never been observed for this "
            f"account before in the analyzed data.",
            "medium", ["T1078.001", "T1078"], "Exploitation", [ev],
            {"users": [s["username"]], "ips": [s["src_ip"]], "hosts": [host or "?"],
             "processes": []})

    group_key = None
    fail_buf: list[dict] = []   # failures within the window for the current group
    first_ts = None

    def flush_group(successes):
        # successes for this group were collected while walking it
        return successes

    successes = []
    while True:
        rows = cur.fetchmany(2000)
        if not rows:
            break
        for r in rows:
            key = (r["username"], r["src_ip"])
            if key != group_key:
                group_key = key
                fail_buf = []
                first_ts = None
            if first_ts is None:
                first_ts = r["ts"]
            if r["event_type"] == "auth_failure":
                fail_buf.append(dict(r))
                # keep only the trailing window
                cutoff = r["ts"] - window_s
                while fail_buf and fail_buf[0]["ts"] < cutoff:
                    fail_buf.pop(0)
            else:
                host = r["host"]
                recent = [f for f in fail_buf if f["ts"] >= r["ts"] - window_s]
                if len(recent) >= min_failures:
                    out.append(make_success_det(r, recent, host))
                if (det_mod.is_external(r["src_ip"])
                        and abs(first_ts - r["ts"]) < 1):
                    hour = det_mod.datetime.fromtimestamp(r["ts"]).hour
                    if hour >= odd_start or hour < odd_end:
                        out.append(make_odd_det(r, host))
                # Any successful admin-interface login from an external IP is
                # inherently suspicious on a perimeter device, regardless of
                # whether failures preceded it.
                if (det_mod.is_external(r["src_ip"]) and r["host"]
                        and ("logged in successfully" in (r["message"] or "").lower()
                             or "login successful" in (r["message"] or "").lower())):
                    ev = {"id": r["id"], "ts": r["ts"], "username": r["username"],
                          "host": host, "src_ip": r["src_ip"], "message": r["message"]}
                    out.append(_mk(
                        "ADMIN_LOGIN_EXTERNAL",
                        "Successful admin login from an external IP", "high",
                        f"Account '{r['username']}' successfully logged into the admin "
                        f"interface of perimeter device {host} from external IP "
                        f"{r['src_ip']} at {det_mod.fmt_time(r['ts'])}. Successful "
                        f"external administration is observed evidence; whether this "
                        f"specific login is the attacker or a legitimate administrator "
                        f"requires verification with the account owner.",
                        "high", ["T1078"], "Exploitation", [ev],
                        {"users": [r["username"]], "ips": [r["src_ip"]],
                         "hosts": [host], "processes": []}))
    return out


def detect_privilege_large(conn: sqlite3.Connection, max_groups=100) -> list[dict]:
    out = []
    rows = conn.execute(
        """SELECT username, host, COUNT(*) c, MIN(ts) t0, MAX(ts) t1
           FROM events WHERE event_type='privilege' AND outcome='failure'
           AND username IS NOT NULL GROUP BY username, host HAVING c >= 2 LIMIT ?""",
        (max_groups,)).fetchall()
    for r in rows:
        evs = [dict(x) for x in conn.execute(
            """SELECT id, ts, username, host, src_ip, message FROM events
               WHERE event_type='privilege' AND outcome='failure' AND username=? AND host=?
               ORDER BY ts LIMIT 50""", (r["username"], r["host"]))]
        out.append(_mk(
            "PRIVILEGE_ESCALATION_ATTEMPT", "Failed privilege escalation (sudo) attempts", "high",
            f"Account '{r['username']}' made {r['c']} failed attempts to elevate privileges on "
            f"{r['host']} ({det_mod.fmt_time(r['t0'])} - {det_mod.fmt_time(r['t1'])}). Attempts "
            f"are observed as FAILED - no successful elevation appears in the evidence.",
            "high", ["T1548.003", "T1078.003"], "Installation", evs,
            {"users": [r["username"]], "ips": [e.get("src_ip") or "?" for e in evs if e.get("src_ip")],
             "hosts": [r["host"]], "processes": ["sudo"]}))
    return out


def detect_port_scan(conn: sqlite3.Connection, min_ports=20, max_groups=100) -> list[dict]:
    """External sources touching many distinct ports on one internal target.

    Two-phase for scale: (1) streaming GROUP BY (index-ordered, no temp b-tree)
    finds candidate pairs with many sessions; (2) per-candidate distinct-port
    counts (few candidates, each an index range scan).
    """
    out = []
    try:
        candidates = conn.execute(
            """SELECT src_ip, dst_ip, COUNT(*) c
               FROM events INDEXED BY idx_net_pair
               WHERE event_type='network' AND dst_port IS NOT NULL
               GROUP BY src_ip, dst_ip HAVING c >= 40 LIMIT 500""").fetchall()
    except sqlite3.OperationalError:
        candidates = conn.execute(
            """SELECT src_ip, dst_ip, COUNT(*) c
               FROM events WHERE event_type='network' AND dst_port IS NOT NULL
               GROUP BY src_ip, dst_ip HAVING c >= 40 LIMIT 500""").fetchall()
    for r in candidates:
        ext_src = det_mod.is_external(r["src_ip"])
        ext_dst = det_mod.is_external(r["dst_ip"])
        if ext_src == ext_dst:
            continue  # only interested in cross-boundary scanning
        meta = conn.execute(
            """SELECT COUNT(DISTINCT dst_port) p, COUNT(*) c, MIN(ts) t0, MAX(ts) t1
               FROM events INDEXED BY idx_net_pair
               WHERE event_type='network' AND src_ip=? AND dst_ip=? AND dst_port IS NOT NULL""",
            (r["src_ip"], r["dst_ip"])).fetchone()
        ports = meta["p"]
        if ports < min_ports:
            continue
        sample = [dict(x) for x in conn.execute(
            """SELECT id, ts, username, host, src_ip, dst_ip, message FROM events
               INDEXED BY idx_net_pair
               WHERE event_type='network' AND src_ip=? AND dst_ip=? LIMIT 40""",
            (r["src_ip"], r["dst_ip"]))]
        direction = ("External scan of an internal host" if ext_src else
                     "Internal host scanning an external system")
        out.append(_mk(
            "PORT_SCAN", "Port scanning / service discovery", "medium",
            f"{direction}: {r['src_ip']} touched {ports} distinct ports on {r['dst_ip']} "
            f"across {meta['c']} events ({det_mod.fmt_time(meta['t0'])} - "
            f"{det_mod.fmt_time(meta['t1'])}). "
            f"Scanning indicates reconnaissance; it does not by itself imply successful access.",
            "medium", ["T1046"], "Reconnaissance", sample,
            {"users": sorted({s["username"] or "?" for s in sample})[:10],
             "ips": [r["src_ip"], r["dst_ip"]],
             "hosts": sorted({s["host"] or "?" for s in sample}), "processes": []}))
        if len(out) >= max_groups:
            break
    return out


def detect_large_transfers(conn: sqlite3.Connection, min_bytes=100_000_000,
                           max_groups=100) -> list[dict]:
    """Large outbound transfers from internal hosts (candidate exfiltration).

    The transfer is OBSERVED; whether it was legitimate or successful exfiltration
    is NOT implied - hence 'candidate'.
    """
    out = []
    rows = conn.execute(
        """SELECT src_ip, dst_ip, COUNT(*) c, SUM(bytes_out) b, MAX(bytes_out) mb,
           MIN(ts) t0, MAX(ts) t1
           FROM events WHERE event_type='network' AND bytes_out >= ?
           AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
           GROUP BY src_ip, dst_ip ORDER BY b DESC LIMIT ?""",
        (min_bytes, max_groups)).fetchall()
    for r in rows:
        internal = not det_mod.is_external(r["src_ip"]) and det_mod.is_external(r["dst_ip"])
        if not internal:
            continue
        sample = [dict(x) for x in conn.execute(
            """SELECT id, ts, username, host, src_ip, dst_ip, message FROM events
               WHERE event_type='network' AND src_ip=? AND dst_ip=? AND bytes_out >= ?
               ORDER BY ts DESC LIMIT 30""", (r["src_ip"], r["dst_ip"], min_bytes))]
        out.append(_mk(
            "DATA_TRANSFER_CANDIDATE", "Large outbound data transfer (candidate, unconfirmed)",
            "medium",
            f"{r['src_ip']} transferred {r['b'] / 1e9:.2f} GB total outbound to external IP "
            f"{r['dst_ip']} across {r['c']} sessions (largest single session "
            f"{r['mb'] / 1e6:.0f} MB). The transfers are observed; whether they are legitimate "
            f"business flows or data exfiltration requires verification - this is a candidate, "
            f"not a confirmed exfiltration.",
            "low", ["T1041"], "Actions on Objectives", sample,
            {"users": sorted({s["username"] or "?" for s in sample})[:10],
             "ips": [r["src_ip"], r["dst_ip"]],
             "hosts": sorted({s["host"] or "?" for s in sample}), "processes": []}))
    return out


def detect_web_threats_blocked(conn: sqlite3.Connection, min_count=10) -> list[dict]:
    """Web filter / antivirus blocks - observed blocks, never implied compromise."""
    out = []
    rows = conn.execute(
        """SELECT host, action, COUNT(*) c, MIN(ts) t0, MAX(ts) t1
           FROM events WHERE action IN ('webfilter', 'virus') AND outcome='failure'
           GROUP BY host, action HAVING c >= ? ORDER BY c DESC LIMIT 50""",
        (min_count,)).fetchall()
    for r in rows:
        kind = "Web threats" if r["action"] == "webfilter" else "Malware downloads"
        sample = [dict(x) for x in conn.execute(
            """SELECT id, ts, username, host, src_ip, dst_ip, message, details FROM events
               WHERE action=? AND outcome='failure' AND host=? ORDER BY ts LIMIT 30""",
            (r["action"], r["host"]))]
        cats = sorted({(db_jcat(x.get("details"))) for x in sample})[:6]
        out.append(_mk(
            "WEB_THREAT_BLOCKED", f"{kind} blocked by security gateway", "medium",
            f"The security gateway on {r['host']} blocked {r['c']:,} "
            f"{kind.lower()} events ({det_mod.fmt_time(r['t0'])} - {det_mod.fmt_time(r['t1'])}). "
            f"Categories observed: {', '.join(cats)}. All were BLOCKED by the gateway - "
            f"these are attempted exposures, not confirmed infections.",
            "high", ["T1189"] if r["action"] == "webfilter" else ["T1203"],
            "Delivery", sample,
            {"users": sorted({s["username"] or "?" for s in sample})[:20],
             "ips": sorted({s["src_ip"] or "?" for s in sample})[:20],
             "hosts": [r["host"]], "processes": []},
            extra={"aggregate": True, "total_events": r["c"]}))
    return out


def detect_ips_alerts(conn: sqlite3.Connection, min_count=10) -> list[dict]:
    out = []
    rows = conn.execute(
        """SELECT host, COUNT(*) c, MIN(ts) t0, MAX(ts) t1
           FROM events WHERE action='ips' AND outcome='failure'
           GROUP BY host HAVING c >= ? ORDER BY c DESC LIMIT 20""", (min_count,)).fetchall()
    for r in rows:
        sample = [dict(x) for x in conn.execute(
            """SELECT id, ts, username, host, src_ip, dst_ip, message FROM events
               WHERE action='ips' AND outcome='failure' AND host=? ORDER BY ts LIMIT 30""",
            (r["host"],))]
        out.append(_mk(
            "IPS_ALERTS", "Intrusion-prevention alerts (traffic dropped)", "medium",
            f"The IPS engine on {r['host']} dropped {r['c']:,} suspicious traffic events "
            f"({det_mod.fmt_time(r['t0'])} - {det_mod.fmt_time(r['t1'])}). Signatures matched "
            f"and the traffic was blocked - attack ATTEMPTS observed, compromise not implied. "
            f"Sources targeting the network repeatedly deserve review.",
            "high", ["T1203"], "Delivery", sample,
            {"users": sorted({s["username"] or "?" for s in sample})[:20],
             "ips": sorted({s["src_ip"] or "?" for s in sample})[:20],
             "hosts": [r["host"]], "processes": []},
            extra={"aggregate": True, "total_events": r["c"]}))
    return out


def db_jcat(details_json) -> str:
    import json
    try:
        d = json.loads(details_json) if isinstance(details_json, str) else (details_json or {})
        return d.get("category") or "uncategorized"
    except Exception:
        return "uncategorized"


def run_streaming_detectors(conn: sqlite3.Connection) -> list[dict]:
    """All SQL-first rules; each returns bounded evidence."""
    detections: list[dict] = []
    detections.extend(detect_credential_spraying(conn))
    detections.extend(detect_targeted_bruteforce(conn))
    detections.extend(detect_pair_bursts(conn))
    detections.extend(detect_auth_transitions_large(conn))
    detections.extend(detect_privilege_large(conn))
    detections.extend(detect_port_scan(conn))
    detections.extend(detect_large_transfers(conn))
    detections.extend(detect_web_threats_blocked(conn))
    detections.extend(detect_ips_alerts(conn))
    # EDR-style rules when process events exist (mixed datasets)
    n_proc = conn.execute("SELECT COUNT(*) c FROM events WHERE event_type='process'").fetchone()["c"]
    if 0 < n_proc <= 200_000:
        from .engine import _load_events_by_type
        detections.extend(det_mod.detect_suspicious_processes(
            _load_events_by_type(conn, "process")))
    detections.sort(key=lambda d: (-(det_mod.SEV_RANK.get(d["severity"], 0)), d["first_ts"] or 0))
    return detections


CREDENTIAL_FAMILY = {"BRUTE_FORCE_AUTH", "SUCCESS_AFTER_FAILURES", "AUTH_SPRAYING",
                     "AUTH_TARGETED_BRUTE", "ADMIN_LOGIN_EXTERNAL"}
