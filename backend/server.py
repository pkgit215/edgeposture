"""Pod-only entrypoint for supervisor.

This module is NOT part of the deployed App Runner image (the Dockerfile
runs `uvicorn main:app` directly). It exists solely so the Emergent pod's
supervisor (`uvicorn server:app`) keeps serving Phase 0 endpoints AND can
expose the build tarball under `/api/dist/` for Cloud9 download.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi.staticfiles import StaticFiles

from main import app  # re-export the deployed app

DIST_DIR = Path("/app/dist")
DIST_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/api/dist", StaticFiles(directory=str(DIST_DIR), html=False), name="dist")

# Reserve the env var
_ = os.environ.get("DEMO_MODE", "true")
