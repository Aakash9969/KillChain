"""Disk-backed storage (SQLite, WAL mode). All raw log evidence is preserved.

Tables:
  sources      - imported log files / demo datasets
  events       - canonical parsed events, always keeping the raw original line
  incidents    - correlated attack incidents produced by the analysis engine
  ingest_jobs  - ingestion job status (streaming progress)
  analyses     - analysis runs (deterministic pipeline, kept for audit)
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Iterable

from . import config

_local = threading.local()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_db() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _connect()
        _local.conn = conn
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,               -- syslog | jsonl
  origin TEXT NOT NULL,             -- demo | upload
  path TEXT NOT NULL,
  uploaded_at REAL NOT NULL,
  total_lines INTEGER DEFAULT 0,
  parsed_events INTEGER DEFAULT 0,
  parse_errors INTEGER DEFAULT 0,
  byte_size INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  line_no INTEGER NOT NULL,
  ts REAL,                          -- unix epoch seconds (may be NULL if unparseable)
  ts_text TEXT,                     -- original timestamp text
  event_type TEXT NOT NULL,         -- auth_failure|auth_success|process|remote_access|privilege|network|file|other
  severity TEXT NOT NULL,           -- info|low|medium|high|critical (intrinsic, pre-detection)
  username TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  dst_port INTEGER,
  host TEXT,
  process TEXT,
  action TEXT,                      -- free-form normalized action e.g. ssh_login, sudo, powershell
  outcome TEXT,                     -- success|failure|unknown
  message TEXT,
  bytes_out INTEGER,                -- bytes sent (firewall/ECS telemetry, 0 if n/a)
  bytes_in INTEGER,                 -- bytes received
  details TEXT,                     -- JSON dict of extra fields
  raw TEXT NOT NULL                 -- ORIGINAL raw log line (evidence)
);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS ingest_jobs (
  id TEXT PRIMARY KEY,
  source_id INTEGER,
  filename TEXT,
  origin TEXT,
  status TEXT NOT NULL,             -- running|done|error|interrupted
  processed_lines INTEGER DEFAULT 0,
  parsed_events INTEGER DEFAULT 0,
  parse_errors INTEGER DEFAULT 0,
  error_text TEXT,
  started_at REAL,
  finished_at REAL,
  -- folder / large-dataset ingestion
  source_dir TEXT,
  files_total INTEGER DEFAULT 0,
  files_done INTEGER DEFAULT 0,
  current_file TEXT,
  total_bytes INTEGER DEFAULT 0,
  bytes_done INTEGER DEFAULT 0,
  records_read INTEGER DEFAULT 0,
  speed_eps REAL DEFAULT 0,         -- parsed events per second
  eta_seconds REAL,                 -- estimated remaining time
  resumable INTEGER DEFAULT 0
);

-- per-file checkpoint state for resumable folder ingestion
CREATE TABLE IF NOT EXISTS ingest_files (
  id INTEGER PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES ingest_jobs(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  name TEXT NOT NULL,
  format TEXT NOT NULL,
  byte_size INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',   -- pending|running|done|error
  byte_offset INTEGER DEFAULT 0,            -- offset after last committed complete line
  line_no INTEGER DEFAULT 0,
  parsed_events INTEGER DEFAULT 0,
  parse_errors INTEGER DEFAULT 0,
  source_id INTEGER,
  error_text TEXT
);
CREATE INDEX IF NOT EXISTS idx_ingest_files_job ON ingest_files(job_id);

CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY,
  started_at REAL,
  finished_at REAL,
  events_analyzed INTEGER,
  detections INTEGER,
  incidents INTEGER,
  status TEXT,
  note TEXT
);

CREATE TABLE IF NOT EXISTS detections (
  id INTEGER PRIMARY KEY,
  analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  explanation TEXT NOT NULL,
  confidence TEXT NOT NULL,
  mitre TEXT NOT NULL,             -- JSON list of technique ids
  killchain_stage TEXT NOT NULL,
  event_ids TEXT NOT NULL,         -- JSON list of event ids
  entities TEXT NOT NULL,          -- JSON dict {users, ips, hosts, processes}
  first_ts REAL, last_ts REAL
);
CREATE INDEX IF NOT EXISTS idx_detections_analysis ON detections(analysis_id);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY,
  analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  ref TEXT NOT NULL,               -- e.g. INC-2026-0001
  name TEXT NOT NULL,
  summary TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  first_ts REAL, last_ts REAL,
  event_ids TEXT NOT NULL,         -- JSON list
  detection_ids TEXT NOT NULL,     -- JSON list
  entities TEXT NOT NULL,          -- JSON dict
  entry_point TEXT,                -- JSON dict describing reconstructed entry point
  progressions TEXT NOT NULL,      -- JSON list of stage descriptors
  hypotheses TEXT NOT NULL,        -- JSON list of hypothesis strings
  is_demo INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_incidents_analysis ON incidents(analysis_id);
"""


def init_db() -> None:
    conn = get_db()
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.commit()


def _migrate(conn: sqlite3.Connection) -> None:
    """Lightweight column migrations for databases created by older versions."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
    for col, ddl in [
        ("dst_port", "ALTER TABLE events ADD COLUMN dst_port INTEGER"),
        ("bytes_out", "ALTER TABLE events ADD COLUMN bytes_out INTEGER"),
        ("bytes_in", "ALTER TABLE events ADD COLUMN bytes_in INTEGER"),
    ]:
        if col not in cols:
            conn.execute(ddl)
    if "idx_events_type" not in {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='events'")}:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
    jcols = {r["name"] for r in conn.execute("PRAGMA table_info(ingest_jobs)")}
    for col, ddl in [
        ("source_dir", "ALTER TABLE ingest_jobs ADD COLUMN source_dir TEXT"),
        ("files_total", "ALTER TABLE ingest_jobs ADD COLUMN files_total INTEGER DEFAULT 0"),
        ("files_done", "ALTER TABLE ingest_jobs ADD COLUMN files_done INTEGER DEFAULT 0"),
        ("current_file", "ALTER TABLE ingest_jobs ADD COLUMN current_file TEXT"),
        ("total_bytes", "ALTER TABLE ingest_jobs ADD COLUMN total_bytes INTEGER DEFAULT 0"),
        ("bytes_done", "ALTER TABLE ingest_jobs ADD COLUMN bytes_done INTEGER DEFAULT 0"),
        ("records_read", "ALTER TABLE ingest_jobs ADD COLUMN records_read INTEGER DEFAULT 0"),
        ("speed_eps", "ALTER TABLE ingest_jobs ADD COLUMN speed_eps REAL DEFAULT 0"),
        ("eta_seconds", "ALTER TABLE ingest_jobs ADD COLUMN eta_seconds REAL"),
        ("resumable", "ALTER TABLE ingest_jobs ADD COLUMN resumable INTEGER DEFAULT 0"),
    ]:
        if col not in jcols:
            conn.execute(ddl)


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


def jload(text: str | None, default: Any = None) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default


def jdump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def now() -> float:
    return time.time()
