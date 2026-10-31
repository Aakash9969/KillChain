"""Fast streaming scan of a FortiGate log to inventory event types (bounded memory)."""
import re
import sys
import time
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else "firex-10G.log"
max_bytes = int(sys.argv[2]) if len(sys.argv) > 2 else 500 * 1024 * 1024

subtypes = Counter()
logids = Counter()
levels = Counter()
login_status = Counter()
login_users = Counter()
login_srcs = Counter()
webfilter_cats = Counter()
services = Counter()
actions = Counter()

t0 = time.time()
n = 0
with open(path, "r", encoding="utf-8", errors="replace") as f:
    while n < max_bytes:
        chunk = f.readlines(64 * 1024 * 1024)  # read ~64MB worth of lines
        if not chunk:
            break
        for line in chunk:
            n += len(line.encode("utf-8", errors="replace"))
            if "subtype=" in line:
                m = re.search(r"subtype=\"?(\w+)", line)
                if m:
                    subtypes[m.group(1)] += 1
            m = re.search(r"logid=\"?(\w+)", line)
            if m:
                logids[m.group(1)] += 1
            m = re.search(r"level=\"?(\w+)", line)
            if m:
                levels[m.group(1)] += 1
            if "action=login" in line or 'action="login"' in line:
                ms = re.search(r"status=\"?(\w+)", line)
                mu = re.search(r" user=\"?([\w.-]+)", line)
                mip = re.search(r"srcip=(\S+)", line)
                if ms:
                    login_status[ms.group(1)] += 1
                if mu:
                    login_users[mu.group(1)] += 1
                if mip:
                    login_srcs[mip.group(1)] += 1
            m = re.search(r"catdesc=\"([^\"]*)\"", line)
            if m:
                webfilter_cats[m.group(1)] += 1
            if "type=traffic" in line:
                ms = re.search(r"service=\"?([\w-]+)", line)
                if ms:
                    services[ms.group(1)] += 1
                ma = re.search(r" action=\"?(\w+)", line)
                if ma:
                    actions[ma.group(1)] += 1

print(f"scanned {n/1e9:.2f} GB in {time.time()-t0:.0f}s")
print("\nsubtypes:", subtypes.most_common(12))
print("\nlogids:", logids.most_common(12))
print("\nlevels:", levels.most_common(8))
print("\nlogin status:", login_status.most_common())
print("login users:", login_users.most_common(15))
print("login src ips (top):", login_srcs.most_common(15))
print("\nwebfilter cats:", webfilter_cats.most_common(15))
print("\ntraffic services:", services.most_common(15))
print("traffic actions:", actions.most_common())
