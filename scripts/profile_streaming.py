"""Time each streaming detector on the large dataset (per-detector breakdown)."""
import sys
import time

sys.path.insert(0, "backend")
import sqlite3  # noqa: E402

from app.analysis import fw_detectors  # noqa: E402

conn = sqlite3.connect("data/killchain.db", timeout=120)
conn.row_factory = sqlite3.Row

total = 0.0
all_dets = []
for name, fn in [
    ("spraying", lambda: fw_detectors.detect_credential_spraying(conn)),
    ("targeted", lambda: fw_detectors.detect_targeted_bruteforce(conn)),
    ("pair_bursts", lambda: fw_detectors.detect_pair_bursts(conn)),
    ("auth_transitions", lambda: fw_detectors.detect_auth_transitions_large(conn)),
    ("port_scan", lambda: fw_detectors.detect_port_scan(conn)),
    ("large_transfers", lambda: fw_detectors.detect_large_transfers(conn)),
    ("web_threats", lambda: fw_detectors.detect_web_threats_blocked(conn)),
    ("ips_alerts", lambda: fw_detectors.detect_ips_alerts(conn)),
]:
    t0 = time.time()
    dets = fn()
    dt = time.time() - t0
    total += dt
    all_dets.extend(dets)
    print(f"{name}: {dt:.1f}s -> {len(dets)} detections", flush=True)

from collections import Counter  # noqa: E402
print(f"TOTAL: {total:.1f}s, {len(all_dets)} detections")
print(Counter(d["rule_id"] for d in all_dets).most_common())
