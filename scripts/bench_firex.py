"""Benchmark: ingest + analyze a large FortiGate dataset via the folder pipeline.

Measures wall time, throughput and peak RSS of the KillChain server process.
Usage: python scripts/bench_firex.py [file name substring] [poll seconds]
"""
import json
import sys
import time

import psutil
import urllib.request

BASE = "http://127.0.0.1:8765/api"


def req(path, data=None, method=None):
    body = json.dumps(data).encode() if data is not None else None
    m = method or ("POST" if body is not None else "GET")
    r = urllib.request.Request(BASE + path, data=body,
                               headers={"Content-Type": "application/json"} if body else {},
                               method=m)
    return json.load(urllib.request.urlopen(r, timeout=600))


def server_proc():
    for p in psutil.process_iter(["name", "cmdline"]):
        try:
            cl = " ".join(p.info["cmdline"] or [])
            if "uvicorn" in cl and "8765" in cl:
                return p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def rss_gb(p):
    try:
        return p.memory_info().rss / 1e9
    except psutil.NoSuchProcess:
        return 0.0


def main():
    needle = sys.argv[1] if len(sys.argv) > 1 else "firex-10G"
    poll_max = int(sys.argv[2]) if len(sys.argv) > 2 else 3600
    proc = server_proc()
    print("server pid:", proc.pid if proc else "NOT FOUND")
    peak_ing = peak_an = 0.0
    sampler_stop = False

    def sampler():
        nonlocal peak_ing, peak_an
        while not sampler_stop:
            for p in psutil.process_iter(["pid", "cmdline"]):
                try:
                    cl = " ".join(p.info["cmdline"] or [])
                    if "uvicorn" in cl and "8765" in cl:
                        peak_ing = max(peak_ing, p.memory_info().rss / 1e9)
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(1)

    import threading
    st = threading.Thread(target=sampler, daemon=True)
    st.start()

    print("== scanning folder ==")
    import os
    scan = req("/ingest/folder/scan", {"path": os.path.abspath(".")})
    files = [f for f in scan["files"] if needle in f["name"]]
    print(f"match: {[(f['name'], round(f['size']/1e9,2), f['format']) for f in files]}")
    if not files:
        print("NO MATCH"); return

    print("== starting folder ingestion ==")
    t0 = time.time()
    job = req("/ingest/folder/start", {"path": scan["directory"],
                                       "files": [f["path"] for f in files]})
    jid = job["job_id"]
    print("job:", jid)

    last = {}
    while time.time() - t0 < poll_max:
        s = req(f"/ingest/status/{jid}")
        if s["status"] in ("done", "error", "interrupted"):
            break
        last = s
        print(f"  {s['status']}: bytes {s.get('bytes_done',0)/1e9:.2f}/"
              f"{s.get('total_bytes',0)/1e9:.2f} GB | events {s.get('parsed_events',0):,} "
              f"| errors {s.get('parse_errors',0):,} | {s.get('speed_eps',0):,.0f} ev/s "
              f"| eta {((s.get('eta_seconds') or 0)/60):.1f} min", flush=True)
        time.sleep(5)
    ing_time = time.time() - t0
    sampler_stop = True
    time.sleep(1.2)
    s = req(f"/ingest/status/{jid}")
    print(f"== ingestion {s['status']} in {ing_time/60:.1f} min | "
          f"events {s.get('parsed_events',0):,} | parse errors {s.get('parse_errors',0):,} | "
          f"peak RSS during ingestion: {peak_ing:.2f} GB ==")

    print("== running analysis (streaming) ==")
    proc2 = server_proc()
    t1 = time.time()
    peak_an = 0.0
    stop2 = False

    def sampler2():
        nonlocal peak_an
        while not stop2:
            peak_an = max(peak_an, rss_gb(proc2))
            time.sleep(1)
    st2 = threading.Thread(target=sampler2, daemon=True)
    st2.start()
    an = req("/analysis/run", {}, method="POST")
    stop2 = True
    an_time = time.time() - t1
    time.sleep(1.2)
    print(f"== analysis {an.get('mode')} done in {an_time/60:.1f} min | "
          f"detections {an['detections']:,} | incidents {an['incidents']:,} | "
          f"peak RSS during analysis: {peak_an:.2f} GB ==")
    print("total peak RSS:", round(max(peak_ing, peak_an), 2), "GB")

    inc = req("/incidents")["incidents"]
    print(f"incidents: {len(inc)}")
    for i in inc[:8]:
        print(f"  {i['ref']} risk={i['risk_score']} sev={i['severity']} :: {i['name'][:80]}")
    with open("scripts/bench_last_result.json", "w") as f:
        json.dump({"file": files[0]["name"], "size_gb": files[0]["size"] / 1e9,
                   "ingest_seconds": ing_time, "ingest_events": s.get("parsed_events", 0),
                   "parse_errors": s.get("parse_errors", 0),
                   "analysis_seconds": an_time, "analysis_mode": an.get("mode"),
                   "detections": an["detections"], "incidents": an["incidents"],
                   "peak_rss_gb": round(max(peak_ing, peak_an), 2),
                   "incidents_preview": inc[:8]}, f, indent=2, default=str)
    print("saved scripts/bench_last_result.json")


if __name__ == "__main__":
    main()
