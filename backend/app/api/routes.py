"""REST API for KillChain."""
from __future__ import annotations

import shutil
import sqlite3
import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from pathlib import Path
from pydantic import BaseModel

from .. import config, db
from ..ai import assistant
from ..analysis import engine
from ..analysis import detectors as det_mod
from ..analysis.graph import build_graph
from ..ingest import demo, pipeline
from ..reports import build_report

router = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# Status & dashboard stats
# ---------------------------------------------------------------------------
@router.get("/status")
def status():
    conn = db.get_db()
    n_events = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    return {"ok": True, "events": n_events, "ai": assistant.ai_status(),
            "data_dir": str(config.DATA_DIR)}


@router.get("/stats")
def stats():
    conn = db.get_db()
    total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    sev_cached = db.get_severity_counts()
    if sev_cached is not None:
        sev_dist = sev_cached
    else:
        sev_dist = {r["severity"]: r["c"] for r in conn.execute(
            "SELECT severity, COUNT(*) c FROM events GROUP BY severity")}

    an_id = engine.latest_analysis_id(conn)
    analysis = None
    detections = []
    suspicious_event_ids: set[int] = set()
    incidents = []
    if an_id:
        arow = conn.execute("SELECT * FROM analyses WHERE id=?", (an_id,)).fetchone()
        analysis = {k: arow[k] for k in ("id", "started_at", "finished_at", "events_analyzed",
                                         "detections", "incidents", "status")}
        detections = [dict(r) for r in conn.execute(
            "SELECT * FROM detections WHERE analysis_id=?", (an_id,))]
        for d in detections:
            suspicious_event_ids.update(db.jload(d["event_ids"], []))
        incidents = [_incident_row(r) for r in conn.execute(
            "SELECT * FROM incidents WHERE analysis_id=? ORDER BY risk_score DESC", (an_id,))]

    crit_high = sum(1 for d in detections if d["severity"] in ("critical", "high"))
    sources = [_source_row(r) for r in conn.execute(
        "SELECT * FROM sources ORDER BY uploaded_at DESC LIMIT 20")]
    jobs = [dict(r) for r in conn.execute(
        "SELECT * FROM ingest_jobs ORDER BY started_at DESC LIMIT 12")]

    return {
        "totals": {
            "events": total,
            "suspicious_events": len(suspicious_event_ids),
            "incidents": len(incidents),
            "detections": len(detections),
            "critical_high_findings": crit_high,
            "sources": len(sources),
        },
        "severity_distribution": sev_dist,
        "recent_incidents": incidents[:5],
        "recent_detections": [_det_row(d) for d in detections[:8]],
        "sources": sources,
        "ingest_jobs": jobs,
        "last_analysis": analysis,
        "ai": assistant.ai_status(),
        "is_demo_data": bool(incidents and all(i.get("is_demo") for i in incidents)),
    }


def _source_row(r) -> dict:
    s = dict(r)
    s["uploaded_at"] = r["uploaded_at"]
    return s


def _det_row(d) -> dict:
    d = dict(d)
    d["mitre"] = db.jload(d["mitre"], [])
    d["event_ids"] = db.jload(d["event_ids"], [])
    d["entities"] = db.jload(d["entities"], {})
    return d


def _incident_row(r) -> dict:
    return {
        "id": r["id"], "ref": r["ref"], "name": r["name"], "summary": r["summary"],
        "risk_score": r["risk_score"], "severity": r["severity"], "status": r["status"],
        "first_ts": r["first_ts"], "last_ts": r["last_ts"], "is_demo": bool(r["is_demo"]),
        "entities": db.jload(r["entities"], {}),
    }


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
class DemoIngestBody(BaseModel):
    pass  # no options needed; endpoint regenerates the synthetic files


class FolderScanBody(BaseModel):
    path: str


class FolderStartBody(BaseModel):
    path: str
    files: list[str]


class FolderResumeBody(BaseModel):
    job_id: str


@router.post("/ingest/demo")
def ingest_demo(body: DemoIngestBody | None = None):
    files = demo.generate_demo_files()
    job_ids = {}
    for name, path in files.items():
        fmt = "jsonl" if name.endswith(".jsonl") else "syslog"
        job_ids[name] = pipeline.start_ingestion(path, name, fmt, origin="demo")
    return {"jobs": job_ids, "note": "SYNTHETIC DEMONSTRATION DATA - generated locally, "
                                     "not real intrusion logs."}


@router.post("/ingest/upload")
async def ingest_upload(file: UploadFile = File(None), files: list[UploadFile] = File(None),
                        fmt: str = "auto"):
    """Upload one or multiple log files; each is ingested through the same pipeline."""
    uploads = [f for f in ([file] if file else []) + (files or []) if f is not None]
    if not uploads:
        raise HTTPException(400, "No files provided")
    updir = config.DATA_DIR / "uploads"
    updir.mkdir(parents=True, exist_ok=True)
    jobs = []
    for f in uploads:
        safe = Path(f.filename or "upload.log").name  # strip any path components
        if not safe or safe in (".", ".."):
            raise HTTPException(400, "Invalid filename")
        dest = updir / f"{uuid.uuid4().hex[:8]}_{safe}"
        with open(dest, "wb") as out:
            shutil.copyfileobj(f.file, out)
        job_id = pipeline.start_ingestion(dest, safe, fmt, origin="upload")
        jobs.append({"job_id": job_id, "filename": safe, "size": dest.stat().st_size})
    return {"jobs": jobs}


@router.post("/ingest/folder/scan")
def folder_scan(body: FolderScanBody):
    from ..ingest import folder
    return folder.scan_folder(body.path)


@router.post("/ingest/folder/start")
def folder_start(body: FolderStartBody):
    from ..ingest import folder
    directory, err = folder.validate_dir(body.path)
    if err:
        raise HTTPException(400, err)
    if not body.files:
        raise HTTPException(400, "No files selected")
    # re-validate every selected file against permitted roots (no traversal)
    for fp in body.files:
        if not folder.path_allowed(Path(fp)):
            raise HTTPException(400, f"File not permitted: {Path(fp).name}")
        p = Path(fp)
        if not p.is_file():
            raise HTTPException(400, f"File not found: {p.name}")
    total_bytes = sum(Path(f).stat().st_size for f in body.files)
    # disk-space pre-flight: normalized events + indexes take roughly 2.5x the
    # raw input in the metadata store; refuse early with a clear message
    free = shutil.disk_usage(config.DATA_DIR).free
    if free < total_bytes * 2.5:
        raise HTTPException(
            400,
            f"Not enough disk space: {total_bytes / 1e9:.1f} GB selected needs roughly "
            f"{total_bytes * 2.5 / 1e9:.1f} GB of storage, but only {free / 1e9:.1f} GB is "
            f"free on {config.DATA_DIR.anchor}. Free space or point KILLCHAIN_DATA_DIR at "
            f"a drive with room.")
    job_id = folder.create_folder_job(str(directory), body.files)
    folder.start_folder_job(job_id)
    return {"job_id": job_id, "files": len(body.files), "total_bytes": total_bytes}


@router.post("/ingest/folder/resume")
def folder_resume(body: FolderResumeBody):
    from ..ingest import folder
    result = folder.resume_job(body.job_id)
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "Resume failed"))
    return result


@router.post("/ingest/edr-gen")
def ingest_edr_gen(count: int = 800, alert_ratio: float = 0.08):
    """Run the hackathon-provided EDR log generator (ECS JSON) and ingest the output."""
    import subprocess
    import sys
    out_dir = config.DATA_DIR / "edr_gen"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "edr_events.json"
    if out_file.exists():
        out_file.unlink()  # the generator appends; start fresh per run
    gen_script = config.APP_ROOT / "edr_log_generator.py"
    if not gen_script.exists():
        raise HTTPException(404, "edr_log_generator.py not found in project root")
    cmd = [sys.executable, str(gen_script), "--count", str(count),
           "--output", "file", "--file", str(out_file), "--rate", "0",
           "--alert-ratio", str(alert_ratio), "--seed", "42"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise HTTPException(500, f"EDR generator failed: {proc.stderr[:300]}")
    job_id = pipeline.start_ingestion(out_file, "edr_events.json (hackathon EDR generator)",
                                      "jsonl", origin="edr_gen")
    return {"job_id": job_id, "events_generated": count,
            "note": "Synthetic EDR telemetry in ECS format produced by the hackathon-provided "
                    "edr_log_generator.py."}


@router.get("/ingest/status/{job_id}")
def ingest_status(job_id: str):
    job = pipeline.JOBS.get(job_id)
    conn = db.get_db()
    files = None
    dbjob = conn.execute("SELECT * FROM ingest_jobs WHERE id=?", (job_id,)).fetchone()
    if dbjob and dbjob["origin"] == "folder":
        files = [dict(r) for r in conn.execute(
            "SELECT id, path, name, format, byte_size, status, byte_offset, line_no, "
            "parsed_events, parse_errors, error_text FROM ingest_files WHERE job_id=? "
            "ORDER BY id", (job_id,))]
        job = {**dict(dbjob), **(job or {})}
    if job is None:
        if dbjob:
            job = dict(dbjob)
        else:
            raise HTTPException(404, "Unknown job")
    if files is not None:
        job["files"] = files
    return job


@router.get("/sources")
def sources():
    conn = db.get_db()
    return [_source_row(r) for r in conn.execute("SELECT * FROM sources ORDER BY uploaded_at DESC")]


# ---------------------------------------------------------------------------
# Events / log explorer
# ---------------------------------------------------------------------------
@router.get("/events")
def list_events(source_id: int | None = None, severity: str | None = None,
                event_type: str | None = None, q: str | None = None,
                limit: int = 200, offset: int = 0):
    conn = db.get_db()
    where, args = ["1=1"], []
    if source_id:
        where.append("source_id=?"); args.append(source_id)
    if severity:
        where.append("severity=?"); args.append(severity)
    if event_type:
        where.append("event_type=?"); args.append(event_type)
    if q:
        where.append("(raw LIKE ? OR username LIKE ? OR host LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ?)")
        args.extend([f"%{q}%"] * 5)
    wh = " AND ".join(where)
    total = conn.execute(f"SELECT COUNT(*) c FROM events WHERE {wh}", args).fetchone()["c"]
    rows = conn.execute(
        f"SELECT id, source_id, line_no, ts, ts_text, event_type, severity, username, src_ip, "
        f"dst_ip, host, process, action, outcome, message FROM events WHERE {wh} "
        f"ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?", (*args, min(limit, 1000), offset)).fetchall()
    return {"total": total, "events": [dict(r) for r in rows]}


@router.get("/events/{event_id}")
def get_event(event_id: int):
    conn = db.get_db()
    row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Event not found")
    e = dict(row)
    e["details"] = db.jload(e.get("details"), {})
    src = conn.execute("SELECT name, kind, origin FROM sources WHERE id=?",
                       (e["source_id"],)).fetchone()
    e["source"] = dict(src) if src else None
    return e


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
@router.post("/analysis/run")
def run_analysis():
    # demo flag: if no user-uploaded (potentially real) sources exist, results are
    # derived purely from synthetic sources and are labelled as demo data
    conn = db.get_db()
    uploads = conn.execute("SELECT COUNT(*) c FROM sources WHERE origin='upload'").fetchone()["c"]
    result = engine.run_analysis(is_demo=uploads == 0)
    return result


@router.get("/detections")
def detections(analysis_id: int | None = None):
    conn = db.get_db()
    an_id = analysis_id or engine.latest_analysis_id(conn)
    if not an_id:
        return {"analysis_id": None, "detections": []}
    rows = conn.execute("SELECT * FROM detections WHERE analysis_id=? "
                        "ORDER BY first_ts", (an_id,)).fetchall()
    return {"analysis_id": an_id, "detections": [_det_row(r) for r in rows]}


@router.get("/incidents")
def incidents():
    conn = db.get_db()
    an_id = engine.latest_analysis_id(conn)
    if not an_id:
        return {"analysis_id": None, "incidents": []}
    rows = conn.execute("SELECT * FROM incidents WHERE analysis_id=? ORDER BY risk_score DESC",
                        (an_id,)).fetchall()
    return {"analysis_id": an_id, "incidents": [_incident_row(r) for r in rows]}


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: int):
    conn = db.get_db()
    inc = engine.get_incident(conn, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    events = engine.get_incident_events(conn, inc["event_ids"])
    dets = engine.get_incident_detections(conn, inc["detection_ids"])
    graph = build_graph(inc, events, dets)
    from ..analysis.lookahead import build_lookahead
    from ..analysis.storyboard import build_storyboard
    det_view = [_det_row({**d, "analysis_id": inc["analysis_id"]}) for d in dets]
    return {"incident": inc, "events": events, "detections": det_view, "graph": graph,
            "storyboard": build_storyboard(inc, events, dets),
            "lookahead": build_lookahead(events, dets)}


@router.get("/incidents/{incident_id}/report")
def incident_report(incident_id: int):
    conn = db.get_db()
    report = build_report(conn, incident_id)
    if report is None:
        raise HTTPException(404, "Incident not found")
    return report


# ---------------------------------------------------------------------------
# Entity explorer
# ---------------------------------------------------------------------------
@router.get("/entities")
def entities():
    conn = db.get_db()
    kinds = {"user": "username", "host": "host", "ip": None}
    out = []
    for kind, col in [("user", "username"), ("host", "host")]:
        rows = conn.execute(
            f"SELECT {col} ident, COUNT(*) cnt, MAX(ts) last_ts FROM events "
            f"WHERE {col} IS NOT NULL AND {col} != '' GROUP BY {col}").fetchall()
        out.extend({"kind": kind, "ident": r["ident"], "event_count": r["cnt"],
                    "last_ts": r["last_ts"]} for r in rows)
    seen: dict[str, dict] = {}
    for r in conn.execute(
            "SELECT ip, cnt, last_ts FROM (SELECT src_ip ip, COUNT(*) cnt, MAX(ts) last_ts "
            "FROM events WHERE src_ip IS NOT NULL GROUP BY src_ip "
            "UNION ALL SELECT dst_ip ip, COUNT(*) cnt, MAX(ts) last_ts FROM events "
            "WHERE dst_ip IS NOT NULL GROUP BY dst_ip)"):
        if r["ip"] in seen:
            seen[r["ip"]]["event_count"] += r["cnt"]
            seen[r["ip"]]["last_ts"] = max(seen[r["ip"]]["last_ts"] or 0, r["last_ts"] or 0)
        else:
            seen[r["ip"]] = {"kind": "ip", "ident": r["ip"], "event_count": r["cnt"],
                             "last_ts": r["last_ts"]}
    out.extend(seen.values())
    # annotate external ips
    for e in out:
        if e["kind"] == "ip":
            e["external"] = det_mod.is_external(e["ident"])
        e["last_seen"] = e.pop("last_ts")
    out.sort(key=lambda x: -(x["event_count"]))
    return out


@router.get("/entities/{kind}/{ident:path}")
def entity_detail(kind: str, ident: str):
    conn = db.get_db()
    if kind == "user":
        col = "username"
    elif kind == "host":
        col = "host"
    elif kind == "ip":
        col = None
    else:
        raise HTTPException(400, "kind must be user, host or ip")
    if col:
        rows = conn.execute(
            f"SELECT id, ts, ts_text, event_type, severity, username, src_ip, dst_ip, host, "
            f"process, action, outcome, message FROM events WHERE {col}=? ORDER BY ts", (ident,)).fetchall()
        where = f"{col}=?"
        args = (ident,)
    else:
        rows = conn.execute(
            "SELECT id, ts, ts_text, event_type, severity, username, src_ip, dst_ip, host, "
            "process, action, outcome, message FROM events WHERE src_ip=? OR dst_ip=? ORDER BY ts",
            (ident, ident)).fetchall()
        where = "(src_ip=? OR dst_ip=?)"
        args = (ident, ident)
    # incidents containing this entity
    incs = []
    an_id = engine.latest_analysis_id(conn)
    if an_id:
        for r in conn.execute("SELECT * FROM incidents WHERE analysis_id=?", (an_id,)):
            ents = db.jload(r["entities"], {})
            pool = set()
            for v in ents.values():
                pool.update(v)
            if ident in pool:
                incs.append(_incident_row(r))
    return {"kind": kind, "ident": ident, "external": det_mod.is_external(ident) if kind == "ip" else None,
            "events": [dict(r) for r in rows], "incidents": incs}


# ---------------------------------------------------------------------------
# AI assistant
# ---------------------------------------------------------------------------
class AskBody(BaseModel):
    question: str


@router.get("/ai/status")
def ai_status():
    return assistant.ai_status()


@router.post("/incidents/{incident_id}/ai")
async def incident_ai(incident_id: int, body: AskBody):
    return await assistant.ask(incident_id, body.question)


# ---------------------------------------------------------------------------
# Admin (demo convenience)
# ---------------------------------------------------------------------------
@router.post("/admin/reset")
def admin_reset():
    """Wipe all data for a clean demonstration run."""
    conn = db.get_db()
    try:
        with conn:  # atomic; rolls back automatically on error
            for table in ("incidents", "detections", "analyses", "events", "ingest_jobs",
                          "ingest_files", "stats_cache", "sources"):
                conn.execute(f"DELETE FROM {table}")
            try:
                conn.execute("DELETE FROM sqlite_sequence")
            except sqlite3.OperationalError:
                pass  # table only exists once AUTOINCREMENT columns are used
    except Exception:
        conn.rollback()
        raise
    return {"ok": True}
