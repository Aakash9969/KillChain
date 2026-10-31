import os
import sys
import tempfile
from pathlib import Path

import pytest

# Isolated data dir BEFORE importing app modules
_TMP = tempfile.mkdtemp(prefix="killchain_test_")
os.environ["KILLCHAIN_DATA_DIR"] = _TMP
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app import config, db  # noqa: E402

config.DB_PATH = Path(_TMP) / "killchain.db"
config.DATA_DIR = Path(_TMP)
config.ALLOWED_DIRS = [os.path.abspath(_TMP), os.path.abspath(
    Path(__file__).resolve().parent.parent)]

from datetime import datetime  # noqa: E402

db.init_db()

from app.ingest import parsers  # noqa: E402
from app.ingest.pipeline import JOBS, start_ingestion  # noqa: E402
from app.analysis import detectors  # noqa: E402
from app.analysis.correlate import build_incidents  # noqa: E402
from app.analysis.engine import run_analysis  # noqa: E402
from app.analysis.storyboard import build_storyboard  # noqa: E402
from app.analysis.lookahead import build_lookahead  # noqa: E402

NOW = datetime(2026, 10, 30, 12, 0, 0)


def ev(i, ts, etype, **kw):
    """Canonical in-memory event for detector tests (mirrors db row shape)."""
    e = {"id": i, "ts": ts, "ts_text": None, "event_type": etype,
         "severity": kw.pop("severity", "info"),
         "username": kw.pop("username", None), "src_ip": kw.pop("src_ip", None),
         "dst_ip": kw.pop("dst_ip", None), "dst_port": kw.pop("dst_port", None),
         "host": kw.pop("host", None), "process": kw.pop("process", None),
         "action": kw.pop("action", None), "outcome": kw.pop("outcome", "unknown"),
         "message": kw.pop("message", None), "bytes_out": kw.pop("bytes_out", 0),
         "bytes_in": kw.pop("bytes_in", 0), "details": kw.pop("details", {}) or {}}
    e.update(kw)
    return e


@pytest.fixture()
def fresh_db():
    # wipe tables instead of deleting the file (avoids Windows file locks from
    # lingering thread-local connections)
    conn = db.get_db()
    for table in ("incidents", "detections", "analyses", "events", "ingest_jobs",
                  "ingest_files", "stats_cache", "sources"):
        try:
            conn.execute(f"DELETE FROM {table}")
        except Exception:
            pass
    conn.commit()
    yield db
