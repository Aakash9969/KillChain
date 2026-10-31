"""KillChain configuration. No secrets are hardcoded here.

AI provider (GLM) is read from environment variables only:
  GLM_API_KEY    - API key for the GLM provider (optional)
  GLM_BASE_URL   - OpenAI-compatible base URL (default: https://api.z.ai/api/paas/v4)
  GLM_MODEL      - model name (default: glm-4.6)
"""
from __future__ import annotations

import os
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = Path(os.environ.get("KILLCHAIN_DATA_DIR", APP_ROOT / "data"))
DEMO_DIR = DATA_DIR / "demo"
DB_PATH = DATA_DIR / "killchain.db"
FRONTEND_DIR = APP_ROOT / "frontend"

# Ingestion batch size for streaming inserts (keeps memory flat for huge files)
INGEST_BATCH_SIZE = 1000

# Allowed roots for local-folder ingestion (path separator ';').
# If unset, only the project directory and its data folder are permitted.
_default_allowed = f"{APP_ROOT};{DATA_DIR}"
ALLOWED_DIRS = [os.path.abspath(p) for p in os.environ.get(
    "KILLCHAIN_ALLOWED_DIRS", _default_allowed).split(";") if p.strip()]

# Analysis strategy: datasets above this event count use the SQL-first
# streaming path (bounded memory); below it the full in-memory path is used.
FULL_SCAN_LIMIT = int(os.environ.get("KILLCHAIN_FULL_SCAN_LIMIT", "200000"))

# Folder ingestion file extensions
FOLDER_EXTENSIONS = {".log", ".jsonl", ".json", ".ndjson", ".txt", ".out"}

# Detection thresholds (deterministic, explainable)
BRUTEFORCE_FAILURE_COUNT = 5          # failed logins ...
BRUTEFORCE_WINDOW_MIN = 30            # ... within this window
SUCCESS_AFTER_FAILURE_WINDOW_MIN = 60
ODD_HOUR_START = 22                   # 22:00
ODD_HOUR_END = 6                      # 06:00
CORRELATION_WINDOW_HOURS = 8          # events linked into one incident must be within this span
CORRELATION_LINK_WINDOW_HOURS = 4     # max gap between linked events on one entity path

DATA_DIR.mkdir(parents=True, exist_ok=True)
DEMO_DIR.mkdir(parents=True, exist_ok=True)

# ---- AI provider (optional) ----
GLM_API_KEY = os.environ.get("GLM_API_KEY", "").strip()
GLM_BASE_URL = os.environ.get("GLM_BASE_URL", "https://api.z.ai/api/paas/v4").strip().rstrip("/")
GLM_MODEL = os.environ.get("GLM_MODEL", "glm-4.6").strip()


def ai_available() -> bool:
    return bool(GLM_API_KEY)
