"""Profile auth-side streaming detectors on the corrected large dataset."""
import sys
import time

sys.path.insert(0, "backend")
import sqlite3  # noqa: E402

conn = sqlite3.connect("data/killchain.db", timeout=120)
conn.row_factory = sqlite3.Row


def timed(label, fn):
    t0 = time.time()
    try:
        r = fn()
        print(f"{label}: {time.time()-t0:.1f}s -> {r}", flush=True)
    except Exception as e:
        print(f"{label}: FAILED after {time.time()-t0:.1f}s: {e}", flush=True)


timed("auth_failure count", lambda: conn.execute(
    "SELECT COUNT(*) FROM events WHERE event_type='auth_failure'").fetchone()[0])
timed("spraying group-by", lambda: len(conn.execute(
    """SELECT src_ip, COUNT(*) c, COUNT(DISTINCT username) users FROM events
       WHERE event_type='auth_failure' AND src_ip IS NOT NULL
       GROUP BY src_ip HAVING c >= 50 AND users >= 10 LIMIT 200""").fetchall()))
timed("targeted group-by", lambda: len(conn.execute(
    """SELECT username, COUNT(*) c, COUNT(DISTINCT src_ip) ips FROM events
       WHERE event_type='auth_failure' AND username IS NOT NULL
       GROUP BY username HAVING c >= 50 AND ips >= 5 LIMIT 100""").fetchall()))
timed("pair-burst group-by", lambda: len(conn.execute(
    """SELECT username, src_ip, COUNT(*) c FROM events
       WHERE event_type='auth_failure' AND username IS NOT NULL AND src_ip IS NOT NULL
       GROUP BY username, src_ip HAVING c >= 30 ORDER BY c DESC LIMIT 200""").fetchall()))


def success_stream():
    cur = conn.execute(
        """SELECT id, ts, username, src_ip, host FROM events
           WHERE event_type='auth_success' AND username IS NOT NULL AND src_ip IS NOT NULL
           ORDER BY ts, id""")
    n = 0
    while True:
        rows = cur.fetchmany(500)
        if not rows:
            break
        n += len(rows)
    return n


timed("success stream (fetch only)", success_stream)


def success_with_lookups():
    cur = conn.execute(
        """SELECT id, ts, username, src_ip, host FROM events
           WHERE event_type='auth_success' AND username IS NOT NULL AND src_ip IS NOT NULL
           ORDER BY ts, id""")
    n = 0
    while True:
        rows = cur.fetchmany(500)
        if not rows:
            break
        for s in rows:
            c = conn.execute(
                """SELECT COUNT(*) c FROM events WHERE event_type='auth_failure'
                   AND username=? AND src_ip=? AND ts IS NOT NULL AND ts BETWEEN ? AND ?""",
                (s["username"], s["src_ip"], s["ts"] - 3600, s["ts"])).fetchone()["c"]
            n += 1
    return n


timed("success stream + per-row COUNT (27k rows)", success_with_lookups)
