# ---------------------------------------------------------------------------
# Streaming path (large datasets): SQL aggregations + bounded evidence
# ---------------------------------------------------------------------------
def _analyze_streaming(conn: sqlite3.Connection):
    detections = fw_detectors.run_streaming_detectors(conn)
    # de-duplicate overlapping rules on identical first-event anchors
    seen: set[tuple] = set()
    uniq = []
    for d in detections:
        key = (d["rule_id"], d["event_ids"][0] if d["event_ids"] else None)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(d)
    detections = uniq

    clusters = _campaign_clusters(detections)
    events = _events_for_detections(conn, detections, clusters)
    seeds = []
    for cluster in clusters:
        eids: set[int] = set()
        for d in cluster:
            eids.update(d["event_ids"][:600])
        seeds.append({"detections": cluster, "core_event_ids": eids})
    return events, detections, seeds


def _events_for_detections(conn: sqlite3.Connection, detections: list[dict],
                           clusters: list[list[dict]], enrich_cap=2000) -> list[dict]:
    """Materialize detection-backed events plus bounded supporting context per
    cluster - never the full dataset."""
    enriched: set[int] = set()
    for cluster in clusters:
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
        if not tss:
            continue
        span0, span1 = min(tss) - 1800, max(tss) + 1800
        q_parts, q_args = [], []
        for u in list(users)[:12]:
            q_parts.append("username=?")
            q_args.append(u)
        for h in list(hosts)[:8]:
            q_parts.append("host=?")
            q_args.append(h)
        if not q_parts:
            continue
        ph = ",".join("?" * len(cluster_ids)) or "NULL"
        rows = conn.execute(
            f"""SELECT id FROM events WHERE ts IS NOT NULL AND ({' OR '.join(q_parts)})
                AND ts BETWEEN ? AND ?
                AND id NOT IN ({ph})
                LIMIT ?""",
            (*q_args, span0, span1, *cluster_ids, enrich_cap))
        for r in rows:
            enriched.add(r["id"])
    out: list[dict] = []
    id_list = sorted(enriched)
    for i in range(0, len(id_list), 900):
        ph = ",".join("?" * len(id_list[i:i + 900]))
        for row in conn.execute(f"SELECT * FROM events WHERE id IN ({ph})",
                                id_list[i:i + 900]):
            e = dict(row)
            e["details"] = db.jload(e.get("details"), {})
            out.append(e)
    out.sort(key=lambda e: (e.get("ts") or 0, e["id"]))
    return out


def _incidents_from_clusters(seeds: list[dict], events: list[dict],
                             detections: list[dict], analysis_id: int,
                             is_demo: bool) -> list[dict]:
    """Assemble incidents from campaign clusters (streaming path).

    All detections in a cluster form ONE incident; its timeline is the cluster's
    detection evidence plus the bounded supporting events loaded for it.
    """
    events_by_id = {e["id"]: e for e in events}
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
        cluster_events = sorted((events_by_id[eid] for eid in eids if eid in events_by_id),
                                key=lambda e: (e.get("ts") or 0, e["id"]))
        if not cluster_events:
            continue
        tss = [e.get("ts") for e in cluster_events if e.get("ts") is not None]
        risk = correlate._risk_score(dets, cluster_events)
        sev = max((d["severity"] for d in dets),
                  key=lambda s: det_mod.SEV_RANK.get(s, 0))
        entry = correlate._find_entry_point(cluster_events)
        hosts_all = sorted({e.get("host") for e in cluster_events if e.get("host")})
        users_all = sorted({e.get("username") for e in cluster_events if e.get("username")})
        ips_all = sorted({ip for e in cluster_events
                          for ip in (e.get("src_ip"), e.get("dst_ip")) if ip})
        top_titles = sorted({d["title"] for d in dets})[:3]
        agg_total = sum(d.get("total_events", 0) for d in dets)
        name = f"{hosts_all[0] if hosts_all else 'Unknown host'} - " \
               f"{top_titles[0].lower() if top_titles else 'suspicious activity'}"
        summary = (f"Correlated campaign spanning {len(cluster_events)} evidence events on "
                   f"{', '.join(hosts_all[:2]) or 'unknown host'} involving account(s) "
                   f"{', '.join(users_all[:4]) or 'multiple'}. Detected behavior: "
                   f"{'; '.join(top_titles)}.")
        if agg_total:
            summary += f" Aggregate evidence covers {agg_total:,} matching events."
        if entry:
            summary += (f" Reconstructed entry point: {entry['description']} "
                        f"(first seen {det_mod.fmt_time(entry['first_seen_ts'])}).")
        ext = sorted({ip for ip in ips_all if det_mod.is_external(ip)})
        if ext:
            summary += f" External infrastructure involved: {', '.join(ext[:5])}."
        incidents.append({
            "analysis_id": analysis_id,
            "ref": "",
            "name": name,
            "summary": summary,
            "risk_score": risk,
            "severity": sev,
            "first_ts": min(tss) if tss else None,
            "last_ts": max(tss) if tss else None,
            "event_ids": [e["id"] for e in cluster_events][:4000],
            "detection_ids": [d["rule_id"] + ":" + str(d["event_ids"][0]) for d in dets],
            "entities": {"users": users_all[:40], "hosts": hosts_all[:10],
                         "ips": ips_all[:40],
                         "processes": sorted({e.get("process") for e in cluster_events
                                              if e.get("process")})},
            "entry_point": entry,
            "hypotheses": [],
            "is_demo": is_demo,
            "_detections": dets,
        })
    incidents.sort(key=lambda i: -i["risk_score"])
    for n, inc in enumerate(incidents, 1):
        inc["ref"] = f"INC-2026-{n:04d}"
    return incidents
