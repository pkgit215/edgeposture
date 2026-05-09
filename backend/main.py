"""RuleIQ FastAPI application — Phase 0.

Endpoints:
    GET  /api/health           — liveness probe
    GET  /api/openapi.json     — OpenAPI schema (relocated under /api)
    POST /api/poc/analyze      — run AI pipeline over fixture WAF rules

Phase 0 is demo-only: no AWS WAF, no MongoDB writes, no background tasks.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from services.ai_pipeline import run_pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ruleiq")

DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() in ("1", "true", "yes")
logger.info("RuleIQ Phase 0 starting | DEMO_MODE=%s", DEMO_MODE)

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "waf_rules.json"


def load_fixture_rules() -> List[Dict[str, Any]]:
    with FIXTURES_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise RuntimeError("waf_rules.json must be a JSON array")
    return data


app = FastAPI(
    title="RuleIQ",
    description="AI-powered AWS WAF audit tool — Phase 0 (POC)",
    version="0.1.0",
    openapi_url="/api/openapi.json",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "phase": "0"}


@app.post("/api/poc/analyze")
def analyze() -> Dict[str, Any]:
    """Run the two-pass AI pipeline over the fixture WAF rules.

    Synchronous in Phase 0 — background tasks land in Phase 1.
    """
    rules = load_fixture_rules()
    logger.info("POC analyze requested | %d fixture rules", len(rules))
    result = run_pipeline(rules)
    return result
