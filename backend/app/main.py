"""KillChain backend entrypoint."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config, db
from .api.routes import router
from .ingest.folder import mark_interrupted_jobs

app = FastAPI(title="KillChain", version="1.0.0",
              description="Cybersecurity attack reconstruction platform")

db.init_db()
mark_interrupted_jobs()  # folder jobs left 'running' by a previous process
app.include_router(router)

# Frontend SPA (registered after /api so API routes take precedence)
if (config.FRONTEND_DIR / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=config.FRONTEND_DIR / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api/"):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        candidate = config.FRONTEND_DIR / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(config.FRONTEND_DIR / "index.html")
