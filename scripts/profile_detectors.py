"""Profile each streaming detector against the ingested large dataset."""
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
        print(f"{label}: {time.time()-t0:.1f}s -> {r}")
    except Exception as e:
        print(f"{label}: FAILED after {time.time()-t0:.1f}s: {e}")


timed("count events", lambda: conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
timed("count auth_failure", lambda: conn.execute(
    "SELECT COUNT(*) FROM events WHERE event_type='auth_failure'").fetchone()[0])
timed("count auth_success", lambda: conn.execute(
    "SELECT COUNT(*) FROM events WHERE event_type='auth_success'").fetchone()[0])
timed("count network", lambda: conn.execute(
    "SELECT COUNT(*) FROM events WHERE event_type='network'").fetchone()[0])

timed("spraying group-by", lambda: len(conn.execute(
    """SELECT src_ip, COUNT(*) c, COUNT(DISTINCT username) users FROM events
       WHERE event_type='auth_failure' AND src_ip IS NOT NULL
       GROUP BY src_ip HAVING c >= 50 AND users >= 10 LIMIT 200""").fetchall()))

timed("targeted group-by", lambda: len(conn.execute(
    """SELECT username, COUNT(*) c, COUNT(DISTINCT src_ip) ips FROM events
       WHERE event_type='auth_failure' AND username IS NOT NULL
       GROUP BY username HAVING c >= 50 AND ips >= 5 LIMIT 100""").fetchall()))

timed("port_scan group-by (indexed?)", lambda: len(conn.execute(
    """SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) ports FROM events
       WHERE event_type='network' AND dst_port IS NOT NULL
       GROUP BY src_ip, dst_ip HAVING ports >= 20 LIMIT 100""").fetchall()))

plan = conn.execute(
    """EXPLAIN QUERY PLAN SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) ports FROM events
       WHERE event_type='network' AND dst_port IS NOT NULL
       GROUP BY src_ip, dst_ip HAVING ports >= 20""").fetchall()
print("port_scan plan:", [tuple(r) for r in plan])
