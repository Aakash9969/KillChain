"""Patch engine.py (per-cluster event scoping) + storyboard.py (flagged-first caps)
+ lookahead.py (internal-only reachable services)."""
import io

# ---- engine.py ----
p = "backend/app/analysis/engine.py"
src = io.open(p, encoding="utf-8").read()

src = src.replace(
    """    clusters = _campaign_clusters(detections)
    events = _events_for_detections(conn, detections, clusters)
    seeds = []
    for cluster in clusters:
        eids: set[int] = set()
        for d in cluster:
            eids.update(d["event_ids"][:600])
        seeds.append({"detections": cluster, "core_event_ids": eids})
    return events, detections, seeds""",
    """    clusters = _campaign_clusters(detections)
    events, cluster_event_ids = _events_for_detections(conn, detections, clusters)
    seeds = []
    for cluster, ceids in zip(clusters, cluster_event_ids):
        eids: set[int] = set()
        for d in cluster:
            eids.update(d["event_ids"][:600])
        eids.update(ceids)
        seeds.append({"detections": cluster, "event_ids": eids})
    return events, detections, seeds""")

src = src.replace(
    """def _events_for_detections(conn: sqlite3.Connection, detections: list[dict],
                           clusters: list[list[dict]], enrich_cap=2000) -> list[dict]:
    \"\"\"Materialize detection-backed events plus bounded supporting context per
    cluster - never the full dataset.\"\"\"
    enriched: set[int] = set()""",
    """def _events_for_detections(conn: sqlite3.Connection, detections: list[dict],
                           clusters: list[list[dict]], enrich_cap=2000):
    \"\"\"Materialize detection-backed events plus bounded supporting context per
    cluster - never the full dataset. Returns (all_events, per_cluster_ids).\"\"\"
    enriched: set[int] = set()
    cluster_event_ids: list[set[int]] = []""")

src = src.replace(
    """    for cluster in clusters:
        cluster_ids: set[int] = set()
        users: set[str] = set()
        hosts: set[str] = set()
        tss: list[float] = []
        for d in cluster:
            cluster_ids.update(d["event_ids"][:600])
            ents = d.get("entities") or {}
            users.update(ents.get("users") or [])
            hosts.update(ents.get("hosts") or [])
            if d.get("first_ts"):
                tss.append(d["first_ts"])
            if d.get("last_ts"):
                tss.append(d["last_ts"])
            enriched.update(cluster_ids)""",
    """    for cluster in clusters:
        cluster_ids: set[int] = set()
        users: set[str] = set()
        hosts: set[str] = set()
        tss: list[float] = []
        for d in cluster:
            cluster_ids.update(d["event_ids"][:600])
            ents = d.get("entities") or {}
            users.update(ents.get("users") or [])
            hosts.update(ents.get("hosts") or [])
            if d.get("first_ts"):
                tss.append(d["first_ts"])
            if d.get("last_ts"):
                tss.append(d["last_ts"])
            enriched.update(cluster_ids)
        cluster_event_ids.append(cluster_ids)""")

src = src.replace(
    """    out.sort(key=lambda e: (e.get("ts") or 0, e["id"]))
    return out


def _incidents_from_clusters""",
    """    out.sort(key=lambda e: (e.get("ts") or 0, e["id"]))
    return out, cluster_event_ids


def _incidents_from_clusters""")

src = src.replace(
    """    events_by_id = {e["id"]: e for e in events}
    incidents = []
    for seed in seeds:
        dets = seed["detections"]
        eids = set(seed["core_event_ids"])
        users: set[str] = set()
        hosts: set[str] = set()
        for d in dets:
            ents = d.get("entities") or {}
            users.update(ents.get("users") or [])
            hosts.update(ents.get("hosts") or [])
        for eid, e in events_by_id.items():
            if eid in eids:
                continue
            if (e.get("username") in users) or (e.get("host") in hosts):
                eids.add(eid)
        cluster_events = sorted((events_by_id[eid] for eid in eids if eid in events_by_id),""",
    """    events_by_id = {e["id"]: e for e in events}
    incidents = []
    for seed in seeds:
        dets = seed["detections"]
        eids = set(seed["event_ids"])
        cluster_events = sorted((events_by_id[eid] for eid in eids if eid in events_by_id),""")

io.open(p, "w", encoding="utf-8", newline="\n").write(src)
print("engine.py patched")

# ---- lookahead.py: internal destinations only for reachable services ----
p = "backend/app/analysis/lookahead.py"
src = io.open(p, encoding="utf-8").read()
src = src.replace(
    """    for (src_host, dst_key, port), svc in remote_services.items():
        if dst_key in accessed_hosts:
            continue
        is_ip = dst_key.replace(".", "").isdigit()""",
    """    for (src_host, dst_key, port), svc in remote_services.items():
        if dst_key in accessed_hosts:
            continue
        # routine outbound internet traffic is not a lateral-movement candidate:
        # only internal-to-internal reachability is relevant for look-ahead
        if det_mod.is_external(svc.get("dst_ip")):
            continue
        is_ip = dst_key.replace(".", "").isdigit()""")
io.open(p, "w", encoding="utf-8", newline="\n").write(src)
print("lookahead.py patched")

# ---- storyboard.py: prioritize flagged events, cap supporting noise ----
p = "backend/app/analysis/storyboard.py"
src = io.open(p, encoding="utf-8").read()
old = """        ph = phases[stage]
        items = sorted(ph["items"], key=lambda i: (i["ts"], i["event_ids"]))
        # cap enormous phases (firewall datasets can produce 100k failed logins)
        if len(items) > 400:
            head = items[:120]
            tail = items[-40:]
            dropped = len(items) - len(head) - len(tail)
            items = head + [{
                "ts": (head[-1]["ts"] + tail[0]["ts"]) / 2,
                "event_ids": [],
                "action": f"... {dropped:,} further events of the same behavior in this phase "
                          f"(aggregate view - full evidence remains queryable in the Log Explorer).",
                "source": {"kind": "info", "id": "agg", "label": "aggregate"},
                "target": {"kind": "info", "id": "agg", "label": "aggregate"},
                "user": None, "host": None, "src_ip": None, "dst_ip": None,
                "process": None, "mitre": [], "stage": stage, "severity": "info",
                "detection": None, "confidence": None, "observed": True,
                "aggregate": True,
            }] + tail"""
new = """        ph = phases[stage]
        all_items = sorted(ph["items"], key=lambda i: (i["ts"], i["event_ids"]))
        flagged = [i for i in all_items if i["detection"]]
        support = [i for i in all_items if not i["detection"]]
        # at campaign scale, unflagged supporting events would drown the story:
        # always show detection-backed steps; cap supporting context hard
        if len(flagged) > 300:
            head = flagged[:150]
            tail = flagged[-50:]
            dropped = len(flagged) - len(head) - len(tail)
            shown_flagged = head + [{
                "ts": (head[-1]["ts"] + tail[0]["ts"]) / 2,
                "event_ids": [],
                "action": f"... {dropped:,} further detected events of the same behavior in "
                          f"this phase (aggregate view - full evidence remains queryable in "
                          f"the Log Explorer).",
                "source": {"kind": "info", "id": "agg", "label": "aggregate"},
                "target": {"kind": "info", "id": "agg", "label": "aggregate"},
                "user": None, "host": None, "src_ip": None, "dst_ip": None,
                "process": None, "mitre": [], "stage": stage, "severity": "info",
                "detection": None, "confidence": None, "observed": True,
                "aggregate": True,
            }] + tail
        else:
            shown_flagged = flagged
        shown_support = [] if flagged else support[:40]
        items = sorted(shown_flagged + shown_support,
                       key=lambda i: (i["ts"], i["event_ids"]))"""
assert old in src
src = src.replace(old, new)
src = src.replace(
    """            "first_ts": items[0]["ts"],
            "last_ts": items[-1]["ts"],
            "item_count": len(ph["items"]),
            "items": items,""",
    """            "first_ts": all_items[0]["ts"],
            "last_ts": all_items[-1]["ts"],
            "item_count": len(all_items),
            "flagged_count": len(flagged),
            "items": items,""")
io.open(p, "w", encoding="utf-8", newline="\n").write(src)
print("storyboard.py patched")
