"""Analysis engine: runs the deterministic pipeline and persists results.

Two strategies, chosen by dataset size (config.FULL_SCAN_LIMIT):
  * full path   - events loaded once, all detectors run in memory (small data)
  * streaming   - SQL-first aggregations with bounded memory (millions of events);
                  incident assembly via campaign clustering over detections
"""
from __future__ import annotations

import sqlite3

from .. import config, db
from . import correlate, detectors, fw_detectors, mitre

det_mod = detectors  # alias used by the streaming incident builder


def run_analysis(is_demo: bool = True) -> dict:
    conn = db.get_db()
    cur = conn.execute(
        "INSERT INTO analyses (started_at, status) VALUES (?, 'running')", (db.now(),))
    analysis_id = cur.lastrowid
    conn.commit()

    try:
        n = conn.execute("SELECT COUNT(*) c FROM events WHERE ts IS NOT NULL").fetchone()["c"]
        mode = "full" if n <= config.FULL_SCAN_LIMIT else "streaming"
        if mode == "streaming":
            # covering index for network aggregations (built once; later runs reuse it)
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_net_pair ON events
                            (src_ip, dst_ip, dst_port) WHERE event_type='network'""")
            conn.commit()
        if mode == "full":
            events, detections = _analyze_full(conn)
            incidents = correlate.build_incidents(events, detections, analysis_id, is_demo)
        else:
            events, detections, incident_seeds = _analyze_streaming(conn)
            incidents = _incidents_from_clusters(incident_seeds, events, detections,
                                                 analysis_id, is_demo)

        for d in detections:
            conn.execute(
                """INSERT INTO detections (analysis_id, rule_id, title, severity, explanation,
                   confidence, mitre, killchain_stage, event_ids, entities, first_ts, last_ts,
                   aggregate, total_events)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (analysis_id, d["rule_id"], d["title"], d["severity"], d["explanation"],
                 d["confidence"], db.jdump(d["mitre"]), d["killchain_stage"],
                 db.jdump(d["event_ids"]), db.jdump(d["entities"]), d["first_ts"], d["last_ts"],
                 1 if d.get("aggregate") else 0, d.get("total_events", 0)))

        for inc in incidents:
            dets = inc.pop("_detections")
            conn.execute(
                """INSERT INTO incidents (analysis_id, ref, name, summary, risk_score, severity,
                   status, first_ts, last_ts, event_ids, detection_ids, entities, entry_point,
                   progressions, hypotheses, is_demo)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (inc["analysis_id"], inc["ref"], inc["name"], inc["summary"], inc["risk_score"],
                 inc["severity"], "open", inc["first_ts"], inc["last_ts"],
                 db.jdump(inc["event_ids"]), db.jdump(inc["detection_ids"]),
                 db.jdump(inc["entities"]), db.jdump(inc.get("entry_point")),
                 db.jdump(_progressions(dets)), db.jdump(inc.get("hypotheses")),
                 1 if is_demo else 0))

        conn.execute(
            """UPDATE analyses SET finished_at=?, status='done', events_analyzed=?,
               detections=?, incidents=?, note=? WHERE id=?""",
            (db.now(), n, len(detections), len(incidents), f"mode={mode}", analysis_id))
        conn.commit()
        db.checkpoint_wal()
        return {
            "analysis_id": analysis_id, "events_analyzed": n,
            "detections": len(detections), "incidents": len(incidents), "status": "done",
            "mode": mode,
        }
    except Exception as exc:
        conn.execute("UPDATE analyses SET finished_at=?, status='error', note=? WHERE id=?",
                     (db.now(), str(exc), analysis_id))
        conn.commit()
        raise


# ---------------------------------------------------------------------------
# Full in-memory path (small/medium datasets) - unchanged behavior
# ---------------------------------------------------------------------------
def _analyze_full(conn: sqlite3.Connection):
    events = []
    for row in conn.execute(
            "SELECT * FROM events WHERE ts IS NOT NULL ORDER BY ts, id"):
        e = dict(row)
        e["details"] = db.jload(e.get("details"), {})
        events.append(e)
    detections = detectors.run_all_detectors(events)
    return events, detections


def _load_events_by_type(conn: sqlite3.Connection, event_type: str, limit=200_000) -> list[dict]:
    out = []
    for row in conn.execute(
            "SELECT * FROM events WHERE event_type=? AND ts IS NOT NULL ORDER BY ts, id LIMIT ?",
            (event_type, limit)):
        e = dict(row)
        e["details"] = db.jload(e.get("details"), {})
        out.append(e)
    return out


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
    events, cluster_event_ids = _events_for_detections(conn, detections, clusters)
    seeds = []
    for cluster, ceids in zip(clusters, cluster_event_ids):
        eids: set[int] = set()
        for d in cluster:
            eids.update(d["event_ids"][:600])
        eids.update(ceids)
        seeds.append({"detections": cluster, "event_ids": eids})
    return events, detections, seeds


def _events_for_detections(conn: sqlite3.Connection, detections: list[dict],
                           clusters: list[list[dict]], enrich_cap=2000):
    """Materialize detection-backed events plus bounded supporting context per
    cluster - never the full dataset. Returns (all_events, per_cluster_ids)."""
    enriched: set[int] = set()
    cluster_event_ids: list[set[int]] = []
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
        cluster_event_ids.append(cluster_ids)
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
    return out, cluster_event_ids


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
        eids = set(seed["event_ids"])
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


def _campaign_clusters(detections: list[dict]) -> list[list[dict]]:
    """Cluster detections into incident seeds.

    Linkage rules (deliberately strict):
      * detections sharing evidence events are linked;
      * credential-attack detections on the same host within 24h are one campaign;
      * credential-attack detections from the same source IP are one campaign;
      * non-credential detections sharing the same host AND overlapping in time
        are linked (e.g. process + lateral movement on one machine).
    """
    n = len(detections)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    # index by event ids
    by_event: dict[int, list[int]] = {}
    for i, d in enumerate(detections):
        for eid in d["event_ids"][:600]:
            by_event.setdefault(eid, []).append(i)
    for group in by_event.values():
        for a, b in zip(group, group[1:]):
            union(a, b)

    for i, d in enumerate(detections):
        ents_i = d.get("entities") or {}
        for j in range(i + 1, min(i + 400, n)):
            e2 = detections[j]
            ents_j = e2.get("entities") or {}
            same_family_cred = (d["rule_id"] in fw_detectors.CREDENTIAL_FAMILY
                                and e2["rule_id"] in fw_detectors.CREDENTIAL_FAMILY)
            hosts_i, hosts_j = set(ents_i.get("hosts") or []), set(ents_j.get("hosts") or [])
            if same_family_cred and hosts_i & hosts_j:
                ti, tj = d.get("first_ts") or 0, e2.get("first_ts") or 0
                if abs(ti - tj) <= 24 * 3600:
                    union(i, j)
                    continue
            if same_family_cred:
                ips_i = set(ents_i.get("ips") or [])
                if ips_i & set(ents_j.get("ips") or []):
                    union(i, j)
                    continue
            if (d["rule_id"] not in fw_detectors.CREDENTIAL_FAMILY
                    and e2["rule_id"] not in fw_detectors.CREDENTIAL_FAMILY
                    and hosts_i & hosts_j):
                ti, tj = d.get("first_ts") or 0, e2.get("first_ts") or 0
                ti2, tj2 = d.get("last_ts") or ti, e2.get("last_ts") or tj
                if ti <= tj2 and tj <= ti2:  # time overlap
                    union(i, j)

    clusters: dict[int, list[dict]] = {}
    for i, d in enumerate(detections):
        clusters.setdefault(find(i), []).append(d)
    return list(clusters.values())


def _progressions(detections: list[dict]) -> list[dict]:
    """Ordered attack progression built from Kill Chain stages of detections."""
    stages: dict[str, list[dict]] = {}
    for d in detections:
        stages.setdefault(d["killchain_stage"], []).append(d)
    ordered = sorted(stages.items(), key=lambda kv: mitre.STAGE_ORDER.get(kv[0], 99))
    out = []
    for stage, dets in ordered:
        out.append({
            "stage": stage,
            "description": dict(mitre.KILL_CHAIN_STAGES).get(stage, ""),
            "detections": [{"rule_id": d["rule_id"], "title": d["title"],
                            "severity": d["severity"], "event_ids": d["event_ids"]}
                           for d in dets],
            "first_ts": min((d["first_ts"] for d in dets if d["first_ts"]), default=None),
        })
    return out


# ---------------------------------------------------------------------------
# Read helpers used by the API layer
# ---------------------------------------------------------------------------
def latest_analysis_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute(
        "SELECT id FROM analyses WHERE status='done' ORDER BY id DESC LIMIT 1").fetchone()
    return row["id"] if row else None


def get_incident(conn: sqlite3.Connection, incident_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        return None
    inc = dict(row)
    inc["event_ids"] = db.jload(inc["event_ids"], [])
    inc["detection_ids"] = db.jload(inc["detection_ids"], [])
    inc["entities"] = db.jload(inc["entities"], {})
    inc["entry_point"] = db.jload(inc.get("entry_point"))
    inc["progressions"] = db.jload(inc.get("progressions"), [])
    inc["hypotheses"] = db.jload(inc.get("hypotheses"), [])
    return inc


def get_incident_events(conn: sqlite3.Connection, event_ids: list[int]) -> list[dict]:
    if not event_ids:
        return []
    ph = ",".join("?" * len(event_ids))
    rows = conn.execute(
        f"SELECT * FROM events WHERE id IN ({ph}) ORDER BY ts, id", event_ids).fetchall()
    out = []
    for r in rows:
        e = dict(r)
        e["details"] = db.jload(e.get("details"), {})
        out.append(e)
    return out


def get_incident_detections(conn: sqlite3.Connection, detection_ids: list[str]) -> list[dict]:
    # detection_ids are "rule_id:first_event_id" pairs; load by rule + first event
    return _load_detections(conn, detection_ids)


def _load_detections(conn: sqlite3.Connection, detection_ids: list[str]) -> list[dict]:
    out = []
    for did in detection_ids:
        rule_id, first_eid = did.split(":", 1)
        row = conn.execute(
            "SELECT * FROM detections WHERE rule_id=? AND event_ids LIKE ? LIMIT 1",
            (rule_id, f"%{first_eid}%")).fetchone()
        if row:
            d = dict(row)
            d["mitre"] = db.jload(d["mitre"], [])
            d["event_ids"] = db.jload(d["event_ids"], [])
            d["entities"] = db.jload(d["entities"], {})
            d["aggregate"] = bool(d.get("aggregate"))
            out.append(d)
    out.sort(key=lambda d: -detectors.SEV_RANK.get(d["severity"], 0))
    return out
