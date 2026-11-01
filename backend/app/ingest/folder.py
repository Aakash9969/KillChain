"""Resumable local-folder ingestion for very large datasets (15-50 GB target).

Flow: validate path against permitted roots -> scan supported files -> per-file
streaming ingestion with byte-offset checkpoints committed at line boundaries ->
progress persisted to the database -> interrupted jobs can resume safely.

Checkpoint safety: plain-text log files are resumed at the stored byte offset of
the last fully-processed line. Compressed formats are not supported for resume
and are rejected up front.
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime
from pathlib import Path

from .. import config, db
from . import parsers
from .pipeline import JOBS

_folder_threads: dict[str, threading.Thread] = {}
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------
def path_allowed(path: Path) -> bool:
    rp = os.path.abspath(str(path))
    for root in config.ALLOWED_DIRS:
        try:
            if rp == os.path.abspath(root) or rp.startswith(os.path.abspath(root).rstrip("\\/") + os.sep):
                return True
        except (ValueError, TypeError):
            continue
    return False


def validate_dir(path_str: str) -> tuple[Path | None, str | None]:
    p = Path(path_str)
    if not p.is_absolute():
        return None, "Path must be absolute (e.g. D:\\SecurityLogs)."
    if not path_allowed(p):
        return None, ("Path is not in the permitted directories. Set the KILLCHAIN_ALLOWED_DIRS "
                      "environment variable (semicolon-separated) to add locations. "
                      f"Currently permitted: {'; '.join(config.ALLOWED_DIRS)}")
    if not p.exists() or not p.is_dir():
        return None, "Directory does not exist or is not a directory."
    return p, None


def scan_folder(path_str: str) -> dict:
    directory, err = validate_dir(path_str)
    if err:
        return {"ok": False, "error": err}
    files = []
    for root, _dirs, names in os.walk(directory):
        for name in names:
            fp = Path(root) / name
            if fp.suffix.lower() not in config.FOLDER_EXTENSIONS:
                continue
            try:
                st = fp.stat()
            except OSError:
                continue
            fmt = peek_format(fp)
            files.append({"path": str(fp), "name": name, "size": st.st_size,
                          "format": fmt or "unknown", "mtime": st.st_mtime})
    files.sort(key=lambda f: -f["size"])
    return {"ok": True, "directory": str(directory), "files": files,
            "total_bytes": sum(f["size"] for f in files)}


def peek_format(fp: Path) -> str | None:
    """Detect format from the first non-empty line."""
    try:
        with open(fp, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    return parsers.detect_format(line)
    except OSError:
        return None
    return None


# ---------------------------------------------------------------------------
# Job lifecycle
# ---------------------------------------------------------------------------
def create_folder_job(directory: str, file_paths: list[str]) -> str:
    job_id = JOBS.create(filename=f"folder: {directory} ({len(file_paths)} files)",
                         origin="folder")
    with _lock:
        JOBS._jobs[job_id].update({
            "source_dir": directory, "files_total": len(file_paths), "files_done": 0,
            "resumable": True,
        })
    conn = db.get_db()
    total_bytes = 0
    for fp in file_paths:
        p = Path(fp)
        size = p.stat().st_size
        total_bytes += size
        fmt = peek_format(p) or "auto"
        conn.execute(
            """INSERT INTO ingest_files (job_id, path, name, format, byte_size, status)
               VALUES (?,?,?,?,?,?)""",
            (job_id, str(p), p.name, fmt, size, "pending"))
    conn.execute("UPDATE ingest_jobs SET total_bytes=?, files_total=?, source_dir=?, "
                 "resumable=1 WHERE id=?", (total_bytes, len(file_paths), directory, job_id))
    conn.commit()
    with _lock:
        JOBS._jobs[job_id]["total_bytes"] = total_bytes
    return job_id


def start_folder_job(job_id: str) -> None:
    with _lock:
        if job_id in _folder_threads and _folder_threads[job_id].is_alive():
            return
        t = threading.Thread(target=_run_folder_job, args=(job_id,), daemon=True)
        _folder_threads[job_id] = t
    t.start()


def resume_job(job_id: str) -> dict:
    """Resume an interrupted folder job from safe byte-offset checkpoints."""
    conn = db.get_db()
    job = conn.execute("SELECT * FROM ingest_jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        return {"ok": False, "error": "Unknown job"}
    if job["origin"] != "folder":
        return {"ok": False, "error": "Only folder jobs can be resumed"}
    if job["status"] == "done":
        return {"ok": False, "error": "Job already completed"}
    pending = conn.execute(
        "SELECT COUNT(*) c FROM ingest_files WHERE job_id=? AND status!='done'",
        (job_id,)).fetchone()["c"]
    if not pending:
        conn.execute("UPDATE ingest_jobs SET status='done', finished_at=? WHERE id=?",
                     (db.now(), job_id))
        conn.commit()
        return {"ok": False, "error": "Nothing to resume - all files completed"}

    # re-arm the in-memory job record from the database
    row = dict(conn.execute("SELECT * FROM ingest_jobs WHERE id=?", (job_id,)).fetchone())
    row["parsed_events"] = 0  # session counters restart; file rows keep totals
    with _lock:
        JOBS._jobs[job_id] = row
    conn.execute("UPDATE ingest_jobs SET status='running', finished_at=NULL, error_text=NULL "
                 "WHERE id=?", (job_id,))
    conn.commit()
    start_folder_job(job_id)
    return {"ok": True, "job_id": job_id, "files_pending": pending}


def mark_interrupted_jobs() -> None:
    """On startup, any folder job still marked 'running' died with the process.
    Tolerates a briefly-locked database (another instance shutting down)."""
    conn = db.get_db()
    for attempt in range(10):
        try:
            conn.execute("UPDATE ingest_jobs SET status='interrupted', error_text="
                         "'Process exited during ingestion - resume available' "
                         "WHERE status='running' AND origin='folder'")
            # analyses left 'running' by a previous process also died
            conn.execute("UPDATE analyses SET status='error', finished_at=?, note="
                         "'Process exited during analysis' WHERE status='running'", (db.now(),))
            conn.commit()
            return
        except sqlite3.OperationalError:
            time.sleep(0.5 * (attempt + 1))
    # non-fatal: the app still starts; stale rows simply keep their status


# ---------------------------------------------------------------------------
# Streaming worker
# ---------------------------------------------------------------------------
def _run_folder_job(job_id: str) -> None:
    conn = db.get_db()
    job_row = conn.execute("SELECT * FROM ingest_jobs WHERE id=?", (job_id,)).fetchone()
    if not job_row:
        return
    directory = job_row["source_dir"]
    files = [dict(r) for r in conn.execute(
        "SELECT * FROM ingest_files WHERE job_id=? AND status!='done' ORDER BY id", (job_id,))]
    session_start = time.time()
    try:
        for frow in files:
            _process_file(job_id, frow, session_start)
        _finalize_job(job_id, directory, session_start)
    except Exception as exc:  # noqa: BLE001 - job must never die silently
        JOBS.update(job_id, status="error", error_text=str(exc)[:500], finished_at=db.now())
    finally:
        db.checkpoint_wal()


def _finalize_job(job_id: str, directory: str, session_start: float) -> None:
    conn = db.get_db()
    agg = conn.execute(
        """SELECT COALESCE(SUM(parsed_events),0) pe, COALESCE(SUM(parse_errors),0) errs,
           COALESCE(SUM(line_no),0) lines, COALESCE(SUM(byte_size),0) bytes
           FROM ingest_files WHERE job_id=?""", (job_id,)).fetchone()
    elapsed = max(time.time() - session_start, 1e-6)
    JOBS.update(job_id, status="done", finished_at=db.now(),
                files_done=agg["lines"] and conn.execute(
                    "SELECT SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) c FROM ingest_files "
                    "WHERE job_id=?", (job_id,)).fetchone()["c"],
                current_file=None,
                parsed_events=agg["pe"], parse_errors=agg["errs"],
                processed_lines=agg["lines"], bytes_done=agg["bytes"],
                records_read=agg["lines"], speed_eps=agg["pe"] / elapsed, eta_seconds=0,
                source_dir=directory, resumable=True)


def _process_file(job_id: str, frow: dict, session_start: float) -> None:
    conn = db.get_db()
    path, fmt = Path(frow["path"]), frow["format"]
    offset = frow["byte_offset"] or 0
    line_no = frow["line_no"] or 0
    parsed = frow["parsed_events"] or 0
    errors = frow["parse_errors"] or 0

    source_id = frow["source_id"]
    if not source_id:
        cur = conn.execute(
            "INSERT INTO sources (name, kind, origin, path, uploaded_at, byte_size) "
            "VALUES (?,?,?,?,?,?)",
            (f"{frow['name']} (folder)", fmt, "folder", str(path), db.now(), frow["byte_size"]))
        conn.commit()
        source_id = cur.lastrowid

    conn.execute("UPDATE ingest_files SET status='running', source_id=? WHERE id=?",
                 (source_id, frow["id"]))
    conn.execute("UPDATE ingest_jobs SET current_file=? WHERE id=?", (frow["name"], job_id))
    conn.commit()

    now_dt = datetime.now()
    batch: list[dict] = []
    last_update = 0.0
    file_start_offset = offset
    consecutive_errors = 0
    skipped_junk = 0

    def flush(final_offset: int) -> None:
        nonlocal parsed, errors, line_no
        if batch:
            conn.executemany(
                """INSERT INTO events (source_id, line_no, ts, ts_text, event_type, severity,
                   username, src_ip, dst_ip, dst_port, host, process, action, outcome, message,
                   bytes_out, bytes_in, details, raw)
                   VALUES (:source_id, :line_no, :ts, :ts_text, :event_type, :severity,
                   :username, :src_ip, :dst_ip, :dst_port, :host, :process, :action, :outcome,
                   :message, :bytes_out, :bytes_in, :details, :raw)""",
                batch)
            db.bump_severity_counts(batch)
            conn.commit()
            batch.clear()
        # checkpoint AFTER committing events: offset = end of last fully-processed line
        conn.execute(
            """UPDATE ingest_files SET byte_offset=?, line_no=?, parsed_events=?,
               parse_errors=?, source_id=? WHERE id=?""",
            (final_offset, line_no, parsed, errors, source_id, frow["id"]))
        conn.commit()

    def update_progress() -> None:
        nonlocal last_update
        nowt = time.time()
        if nowt - last_update < 0.5:
            return
        last_update = nowt
        c = conn.execute(
            """SELECT
                 (SELECT COALESCE(SUM(CASE WHEN status='done' THEN byte_size ELSE byte_offset END),0)
                  FROM ingest_files WHERE job_id=?) bytes_done,
                 (SELECT COUNT(*) FROM ingest_files WHERE job_id=? AND status='done') files_done,
                 (SELECT COUNT(*) FROM ingest_files WHERE job_id=?) files_total,
                 (SELECT COALESCE(SUM(parsed_events),0) FROM ingest_files WHERE job_id=?) parsed,
                 (SELECT COALESCE(SUM(parse_errors),0) FROM ingest_files WHERE job_id=?) errs,
                 (SELECT COALESCE(SUM(line_no),0) FROM ingest_files WHERE job_id=?) lines""",
            (job_id, job_id, job_id, job_id, job_id, job_id)).fetchone()
        job = conn.execute("SELECT total_bytes, started_at FROM ingest_jobs WHERE id=?",
                           (job_id,)).fetchone()
        total_bytes = job["total_bytes"] or 0
        bytes_done = c["bytes_done"] or 0
        session_bytes = bytes_done - file_start_offset if _is_current_file(job_id, frow["id"]) else bytes_done
        elapsed = max(nowt - session_start, 1e-6)
        speed_bps = max(session_bytes, 0) / elapsed
        JOBS.update(job_id, bytes_done=bytes_done,
                    records_read=c["lines"] or 0,
                    processed_lines=c["lines"] or 0,
                    parsed_events=c["parsed"] or 0, parse_errors=c["errs"] or 0,
                    speed_eps=(c["parsed"] or 0) / elapsed,
                    eta_seconds=(total_bytes - bytes_done) / speed_bps if speed_bps > 0 else None,
                    files_done=c["files_done"] or 0, files_total=c["files_total"] or 0,
                    current_file=frow["name"])

    def _is_current_file(job_id: str, file_id: int) -> bool:
        row = conn.execute(
            "SELECT id FROM ingest_files WHERE job_id=? AND status!='done' ORDER BY id LIMIT 1",
            (job_id,)).fetchone()
        return bool(row and row["id"] == file_id)

    with open(path, "rb") as fh:
        fh.seek(offset)
        pending = b""
        while True:
            chunk = fh.read(4 * 1024 * 1024)
            if chunk:
                pending += chunk
            if not chunk and not pending:
                break  # EOF and nothing left to process
            nl = pending.rfind(b"\n")
            if nl == -1:
                if chunk:
                    continue  # no complete line yet; read more
                block, pending = pending, b""  # final line without trailing newline
            else:
                block, pending = pending[:nl + 1], pending[nl + 1:]
            block_offset = offset
            for raw in block.split(b"\n"):
                consumed = len(raw) + 1
                if raw.strip() == b"":
                    block_offset += consumed if raw else 1
                    continue
                # Binary-junk resilience: corrupted/padded regions produce long runs
                # of unparseable lines. Skip forward to the next plausible record
                # instead of counting millions of failures.
                if consecutive_errors >= 200:
                    idx = raw.find(b"eventtime=")
                    if idx == -1:
                        skipped_junk += consumed
                        block_offset += consumed
                        continue
                    raw = raw[idx:]
                    consumed = len(raw) + 1
                    block_offset += idx
                    consecutive_errors = 0
                line_no += 1
                text = raw.decode("utf-8", errors="replace").rstrip("\r")
                block_offset += consumed
                fmt2 = fmt if fmt not in (None, "auto", "unknown") else parsers.detect_format(text)
                ev = None
                try:
                    if fmt2 == "jsonl":
                        ev = parsers.parse_jsonl_line(text, now_dt)
                    elif fmt2 == "syslog":
                        ev = parsers.parse_syslog_line(text, now_dt)
                    elif fmt2 == "fortigate":
                        ev = parsers.parse_fortigate_line(text, now_dt)
                except Exception:
                    ev = None
                if ev is None:
                    errors += 1
                    consecutive_errors += 1
                else:
                    consecutive_errors = 0
                    ev.update(source_id=source_id, line_no=line_no, raw=text)
                    ev["details"] = db.jdump(ev.get("details") or {})
                    batch.append(ev)
                    parsed += 1
                if len(batch) >= config.INGEST_BATCH_SIZE:
                    flush(block_offset)
                    update_progress()
            offset = block_offset
            flush(offset)
            update_progress()
        if skipped_junk:
            conn.execute("UPDATE ingest_files SET error_text=? WHERE id=?",
                         (f"{skipped_junk:,} bytes of non-log/binary content skipped "
                          f"(corrupted or padding region)", frow["id"]))
            conn.commit()

    conn.execute("UPDATE sources SET total_lines=?, parsed_events=?, parse_errors=? WHERE id=?",
                 (line_no, parsed, errors, source_id))
    conn.commit()
    conn.execute("UPDATE ingest_files SET status='done', byte_offset=?, line_no=?, "
                 "parsed_events=?, parse_errors=? WHERE id=?",
                 (offset, line_no, parsed, errors, frow["id"]))
    conn.commit()
