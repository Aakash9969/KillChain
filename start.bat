@echo off
REM KillChain launcher — starts the backend + frontend on http://127.0.0.1:8000
cd /d "%~dp0"
if not exist .venv (
  echo Creating virtual environment...
  python -m venv .venv
  .venv\Scripts\pip install --quiet fastapi "uvicorn[standard]" python-multipart httpx
)
echo Starting KillChain on http://127.0.0.1:8765 ...
start "" http://127.0.0.1:8765
.venv\Scripts\python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8765
