"""Verify storyboard + look-ahead + report on the large-dataset incidents."""
import json
import urllib.request

BASE = "http://127.0.0.1:8765/api"


def get(path):
    return json.load(urllib.request.urlopen(BASE + path, timeout=600))


inc = get("/incidents")["incidents"]
print(f"incidents: {len(inc)}")

# find the odd-hour incident and the top campaign incident
odd = next((i for i in inc if "business hours" in i["name"]), None)
top = inc[0]
for label, i in [("TOP CAMPAIGN", top), ("ODD-HOUR", odd)]:
    if not i:
        continue
    d = get(f"/incidents/{i['id']}")
    sb = d["storyboard"]
    la = d["lookahead"]
    print(f"\n===== {label}: {d['incident']['ref']} risk={d['incident']['risk_score']} "
          f"sev={d['incident']['severity']} =====")
    print("summary:", d["incident"]["summary"][:300])
    print("entry point:", (d["incident"]["entry_point"] or {}).get("description", "none")[:160])
    print("storyboard phases:", [(p["stage"], p["item_count"]) for p in sb["phases"]])
    print("unsupported stages:", sb["unsupported_stages"])
    for p in sb["phases"][:2]:
        for it in p["items"][:3]:
            print(f"  {p['stage'][:12]:12} | {it['action'][:120]}")
    print("lookahead targets:", [(t["target"]["label"], t["confidence"], t["label"]) for t in la["targets"][:5]])
    print("missing info count:", len(la["missing_information"]))
    if label == "TOP CAMPAIGN":
        rep = get(f"/incidents/{i['id']}/report")
        print("report md chars:", len(rep["markdown"]))
        print("confirmed findings:", len(rep["confirmed_findings"]),
              "| techniques:", len(rep["mitre_mapping"]))
