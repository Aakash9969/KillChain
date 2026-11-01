"""Run detect_port_scan alone with a stack dump on timeout."""
import faulthandler
import sys
import time

sys.path.insert(0, "backend")
import sqlite3  # noqa: E402

from app.analysis import fw_detectors  # noqa: E402

faulthandler.dump_traceback_later(60, exit=True)

conn = sqlite3.connect("data/killchain.db", timeout=120)
conn.row_factory = sqlite3.Row

t0 = time.time()
dets = fw_detectors.detect_port_scan(conn)
print(f"port_scan: {time.time()-t0:.1f}s -> {len(dets)} detections", flush=True)
