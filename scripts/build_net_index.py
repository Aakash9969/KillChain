"""One-time: build the partial network index on the ingested large dataset."""
import sys
import time

import sqlite3

t0 = time.time()
conn = sqlite3.connect("data/killchain.db", timeout=120)
n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
print(f"events: {n:,}")
conn.execute(
    "CREATE INDEX IF NOT EXISTS idx_net_pair ON events (src_ip, dst_ip, dst_port) "
    "WHERE event_type='network'")
conn.commit()
print(f"network index built in {time.time() - t0:.0f}s")
