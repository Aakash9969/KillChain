"""Streaming ingestion pipeline.

Reads log files line-by-line in batches (never loading whole files into memory),
writes canonical events to disk-backed SQLite while preserving every raw line,
and reports progress to a job registry.
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime
from pathlib import Path

from .. import config, db
from . import parsers


class JobRegistry:
    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, filename: str, origin: str) -> str:
        job_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._jobs[job_id] = {
                "id": job_id, "filename": filename, "origin": origin,
                "status": "running", "processed_lines": 0, "parsed_events": 0,
                "parse_errors": 0, "error_text": None,
                "started_at": db.now(), "finished_at": None, "source_id": None,
            }
            self._persist(job_id)
        return job_id

    def update(self, job_id: str, **fields) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.update(fields)
            self._persist(job_id)

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            return dict(self._jobs.get(job_id)) if job_id in self._jobs else None

    def _persist(self, job_id: str) -> None:
        job = self._jobs[job_id]
        conn = db.get_db()
        conn.execute(
            """INSERT INTO ingest_jobs (id, source_id, filename, origin, status, processed_lines,
               parsed_events, parse_errors, error_text, started_at, finished_at, source_dir,
               files_total, files_done, current_file, total_bytes, bytes_done, records_read,
               speed_eps, eta_seconds, resumable)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 source_id=excluded.source_id, status=excluded.status,
                 processed_lines=excluded.processed_lines, parsed_events=excluded.parsed_events,
                 parse_errors=excluded.parse_errors, error_text=excluded.error_text,
                 finished_at=excluded.finished_at, source_dir=excluded.source_dir,
                 files_total=excluded.files_total, files_done=excluded.files_done,
                 current_file=excluded.current_file, total_bytes=excluded.total_bytes,
                 bytes_done=excluded.bytes_done, records_read=excluded.records_read,
                 speed_eps=excluded.speed_eps, eta_seconds=excluded.eta_seconds,
                 resumable=excluded.resumable""",
            (job["id"], job.get("source_id"), job["filename"], job["origin"], job["status"],
             job["processed_lines"], job["parsed_events"], job["parse_errors"],
             job["error_text"], job["started_at"], job["finished_at"],
             job.get("source_dir"), job.get("files_total", 0), job.get("files_done", 0),
             job.get("current_file"), job.get("total_bytes", 0), job.get("bytes_done", 0),
             job.get("records_read", 0), job.get("speed_eps", 0), job.get("eta_seconds"),
             1 if job.get("resumable") else 0))
        conn.commit()


JOBS = JobRegistry()


def _ingest_stream(job_id: str, source_id: int, path: Path, format_hint: str) -> None:
    """Stream a file line by line, batch-insert canonical events."""
    now = datetime.now()
    batch: list[dict] = []
    processed = parsed = errors = 0
    conn = db.get_db()
    last_flush = db.now()

    def flush() -> None:
        if not batch:
            return
        conn.executemany(
            """INSERT INTO events (source_id, line_no, ts, ts_text, event_type, severity,
               username, src_ip, dst_ip, dst_port, host, process, action, outcome, message,
               bytes_out, bytes_in, details, raw)
               VALUES (:source_id, :line_no, :ts, :ts_text, :event_type, :severity,
               :username, :src_ip, :dst_ip, :dst_port, :host, :process, :action, :outcome, :message,
               :bytes_out, :bytes_in, :details, :raw)""",
            batch)
        db.bump_severity_counts(batch)
        conn.commit()
        batch.clear()

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, start=1):
            raw = raw.rstrip("\r\n")
            processed += 1
            if not raw.strip():
                continue
            fmt = format_hint if format_hint != "auto" else parsers.detect_format(raw)
            parsed_ev = None
            try:
                if fmt == "jsonl":
                    parsed_ev = parsers.parse_jsonl_line(raw, now)
                elif fmt == "syslog":
                    parsed_ev = parsers.parse_syslog_line(raw, now)
                elif fmt == "fortigate":
                    parsed_ev = parsers.parse_fortigate_line(raw, now)
            except Exception:  # a malformed line must never kill ingestion
                parsed_ev = None
            if parsed_ev is None:
                errors += 1
            else:
                parsed_ev.update(source_id=source_id, line_no=line_no, raw=raw)
                parsed_ev["details"] = db.jdump(parsed_ev.get("details") or {})
                batch.append(parsed_ev)
                parsed += 1

            if len(batch) >= config.INGEST_BATCH_SIZE or (db.now() - last_flush) > 1.0:
                flush()
                last_flush = db.now()
                JOBS.update(job_id, processed_lines=processed, parsed_events=parsed,
                            parse_errors=errors)
    flush()

    conn.execute(
        "UPDATE sources SET total_lines=?, parsed_events=?, parse_errors=? WHERE id=?",
        (processed, parsed, errors, source_id))
    conn.commit()
    JOBS.update(job_id, status="done", processed_lines=processed, parsed_events=parsed,
                parse_errors=errors, finished_at=db.now(), source_id=source_id)


def start_ingestion(path: Path, name: str, fmt: str, origin: str) -> str:
    """Register a source and begin streaming ingestion in a background thread."""
    conn = db.get_db()
    size = path.stat().st_size
    cur = conn.execute(
        "INSERT INTO sources (name, kind, origin, path, uploaded_at, byte_size) VALUES (?,?,?,?,?,?)",
        (name, fmt, origin, str(path), db.now(), size))
    conn.commit()
    source_id = cur.lastrowid
    job_id = JOBS.create(filename=name, origin=origin)

    t = threading.Thread(target=_ingest_stream, args=(job_id, source_id, path, fmt), daemon=True)
    t.start()
    return job_id
