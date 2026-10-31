"""Analysis engine: runs the deterministic pipeline and persists results."""
from __future__ import annotations

import sqlite3

from .. import db
from . import correlate, detectors, mitre


def run_analysis(is_demo: bool = True) -> dict:
    conn = db.get_db()
    cur = conn.execute(
        "INSERT INTO analyses (started_at, status) VALUES (?, 'running')", (db.now(),))
    analysis_id = cur.lastrowid
    conn.commit()

    try:
        events = []
        for row in conn.execute(
                "SELECT * FROM events WHERE ts IS NOT NULL ORDER BY ts, id"):
            e = dict(row)
            e["details"] = db.jload(e.get("details"), {})
            events.append(e)

        detections = detectors.run_all_detectors(events)
        incidents = correlate.build_incidents(events, detections, analysis_id, is_demo)

        for d in detections:
            conn.execute(
                """INSERT INTO detections (analysis_id, rule_id, title, severity, explanation,
                   confidence, mitre, killchain_stage, event_ids, entities, first_ts, last_ts)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (analysis_id, d["rule_id"], d["title"], d["severity"], d["explanation"],
                 d["confidence"], db.jdump(d["mitre"]), d["killchain_stage"],
                 db.jdump(d["event_ids"]), db.jdump(d["entities"]), d["first_ts"], d["last_ts"]))

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
               detections=?, incidents=? WHERE id=?""",
            (db.now(), len(events), len(detections), len(incidents), analysis_id))
        conn.commit()
        return {
            "analysis_id": analysis_id, "events_analyzed": len(events),
            "detections": len(detections), "incidents": len(incidents), "status": "done",
        }
    except Exception as exc:
        conn.execute("UPDATE analyses SET finished_at=?, status='error', note=? WHERE id=?",
                     (db.now(), str(exc), analysis_id))
        conn.commit()
        raise


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
            out.append(d)
    out.sort(key=lambda d: -detectors.SEV_RANK.get(d["severity"], 0))
    return out
