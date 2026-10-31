"""Sample interesting FortiGate event types from firex-10G.log (bounded)."""
import itertools
import re
from collections import Counter

path = "firex-10G.log"
types = Counter()
admin_ok, vpn, ips_ev, virus, vpn_users = [], [], [], [], Counter()
n = 0
with open(path, encoding="utf-8", errors="replace") as f:
    for line in itertools.islice(f, 4000000):
        n += 1
        m = re.search(r'type="?(\w+)', line)
        if m:
            types[m.group(1)] += 1
        if "0100032101" in line and len(admin_ok) < 3:
            admin_ok.append(line.strip()[:420])
        if 'subtype="vpn"' in line:
            if len(vpn) < 3:
                vpn.append(line.strip()[:420])
            mu = re.search(r' user="?([\w.-]+)', line)
            ms = re.search(r'status="?(\w+)', line)
            if mu and ms:
                vpn_users[(mu.group(1), ms.group(1))] += 1
        if 'subtype="ips"' in line and len(ips_ev) < 2:
            ips_ev.append(line.strip()[:400])
        if 'subtype="virus"' in line and len(virus) < 2:
            virus.append(line.strip()[:400])

print("lines:", n, "types:", types.most_common())
print()
print("ADMIN 0100032101 samples:")
for s in admin_ok:
    print("  ", s)
print()
print("VPN samples:")
for s in vpn:
    print("  ", s)
print("vpn user/status:", vpn_users.most_common(10))
print()
print("IPS sample:", ips_ev[0][:380] if ips_ev else None)
print()
print("VIRUS sample:", virus[0][:380] if virus else None)
