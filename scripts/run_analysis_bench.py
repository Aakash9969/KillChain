"""Run analysis on the already-ingested large dataset with RSS monitoring."""
import json
import threading
import time

import psutil
import urllib.request

BASE = "http://127.0.0.1:8765/api"


def server_proc():
    for p in psutil.process_iter(["cmdline"]):
        try:
            if "uvicorn" in " ".join(p.info["cmdline"] or []) and "8765" in " ".join(p.info["cmdline"]):
                return p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


peak = 0.0
stop = False


def sampler():
    global peak
    while not stop:
        p = server_proc()
        if p:
            try:
                peak = max(peak, p.memory_info().rss / 1e9)
            except psutil.NoSuchProcess:
                pass
        time.sleep(1)


req = urllib.request.Request(BASE + "/analysis/run", data=b"{}",
                             headers={"Content-Type": "application/json"}, method="POST")
t0 = time.time()
st = threading.Thread(target=sampler, daemon=True)
st.start()
an = json.load(urllib.request.urlopen(req, timeout=3600))
stop = True
time.sleep(1.2)
print(f"analysis: {an}")
print(f"wall time: {(time.time()-t0)/60:.1f} min | peak RSS: {peak:.2f} GB")

inc = json.load(urllib.request.urlopen(BASE + "/incidents", timeout=60))["incidents"]
print(f"incidents: {len(inc)}")
for i in inc[:10]:
    print(f"  {i['ref']} risk={i['risk_score']} sev={i['severity']} :: {i['name'][:90]}")
with open("scripts/bench_last_result.json", "w") as f:
    json.dump({"analysis": an, "analysis_wall_min": (time.time() - t0) / 60,
               "peak_rss_gb": round(peak, 2), "incidents": inc[:10]}, f, indent=2, default=str)
print("saved scripts/bench_last_result.json")
