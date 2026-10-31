"""Quick FortiGate parser throughput + correctness test on real data."""
import sys
import time
from collections import Counter
from datetime import datetime
from itertools import islice

sys.path.insert(0, "backend")
from app.ingest.parsers import parse_jsonl_line  # noqa: E402

now = datetime.now()
t0 = time.time()
n = ok = err = 0
types = Counter()
sev = Counter()
sample = None
with open("firex-10G.log", encoding="utf-8", errors="replace") as f:
    for line in islice(f, 200000):
        n += 1
        ev = parse_jsonl_line(line, now)
        if ev is None:
            err += 1
        else:
            ok += 1
            types[ev["event_type"]] += 1
            sev[ev["severity"]] += 1
            if sample is None and ev["event_type"] == "auth_failure":
                sample = {k: v for k, v in ev.items() if k not in ("raw", "details")}
            if ok == 120000:
                break
dt = time.time() - t0
print(f"parsed {ok}/{n} errors={err} in {dt:.1f}s -> {ok/dt:,.0f} events/s")
print("types:", types.most_common())
print("severities:", sev.most_common())
print("sample auth_failure:", sample)
