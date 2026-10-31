"""Full-file fast scan for successful logins in firex-10G.log."""
import re
import time
from collections import Counter

path = "firex-10G.log"
admin_success = Counter()
vpn_success = Counter()
vpn_fail = Counter()
samples = []
t0 = time.time()
n = 0
with open(path, encoding="utf-8", errors="replace") as f:
    for line in f:
        n += 1
        if 'action="login"' in line or "action=login" in line:
            if 'status="success"' in line or "status=success" in line:
                mu = re.search(r' user="?([\w.-]+)', line)
                mip = re.search(r"srcip=(\S+)", line)
                admin_success[(mu.group(1) if mu else "?", mip.group(1) if mip else "?")] += 1
                if len(samples) < 3:
                    samples.append(line.strip()[:400])
        elif 'action="ssl-login"' in line:
            mu = re.search(r' user="?([\w.-]+)', line)
            ms = re.search(r'status="?(\w+)', line)
            mip = re.search(r"srcip=(\S+)", line)
            key = (mu.group(1) if mu else "?", mip.group(1) if mip else "?")
            if ms and ms.group(1) == "success":
                vpn_success[key] += 1
            else:
                vpn_fail[key] += 1

print(f"scanned {n:,} lines in {time.time()-t0:.0f}s")
print("admin SUCCESS logins:", admin_success.most_common(10))
for s in samples:
    print("  ", s)
print()
print("vpn ssl-login SUCCESS (user, srcip):", vpn_success.most_common(20))
print("distinct vpn success users:", len(set(u for u, _ in vpn_success)))
print("vpn ssl-login FAIL (top):", vpn_fail.most_common(5))
