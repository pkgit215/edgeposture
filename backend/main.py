"""RuleIQ FastAPI application — Phase 1.

Phase 0 endpoints kept for back-compat (`/api/health`, `/api/openapi.json`,
`/api/poc/analyze`). Phase 1 adds the audit lifecycle:

    POST /api/audits                 -> 202 + audit_run_id
    GET  /api/audits                 -> newest 50 runs
    GET  /api/audits/{id}            -> single run
    GET  /api/audits/{id}/rules      -> rules persisted for this run
    GET  /api/audits/{id}/findings   -> findings sorted by severity_score
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from models import AuditCreateRequest
from services import audit as audit_mod
from services import db as db_mod
from services import seed as seed_mod
from services.ai_pipeline import run_pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ruleiq")

DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() in ("1", "true", "yes")
TESTING = os.environ.get("RULEIQ_TESTING", "0") == "1"
logger.info(
    "RuleIQ Phase 1 starting | DEMO_MODE=%s TESTING=%s", DEMO_MODE, TESTING
)

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "waf_rules.json"


def load_fixture_rules() -> List[Dict[str, Any]]:
    with FIXTURES_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise RuntimeError("waf_rules.json must be a JSON array")
    return data


app = FastAPI(
    title="RuleIQ",
    description="AI-powered AWS WAF audit tool — Phase 1",
    version="0.2.0",
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


@app.on_event("startup")
def _startup() -> None:
    if TESTING:
        logger.info("RULEIQ_TESTING=1 — skipping startup seed and Mongo connect")
        return
    try:
        seed_mod.ensure_demo_seed()
    except Exception as exc:  # noqa: BLE001
        # Defensive: never let seeding kill startup. App Runner probe must stay 200.
        logger.warning("ensure_demo_seed raised, continuing: %s", exc)


# ---------- Health / OpenAPI ---------------------------------------------------


@app.get("/api/health")
def health() -> Dict[str, str]:
    body = {"status": "ok", "phase": "1"}
    if TESTING:
        body["mongo"] = "ok" if db_mod.ping() else "unreachable"
    else:
        body["mongo"] = "ok" if db_mod.ping() else "unreachable"
    return body


# ---------- Phase 0 back-compat ------------------------------------------------


@app.post("/api/poc/analyze")
def analyze() -> Dict[str, Any]:
    rules = load_fixture_rules()
    logger.info("POC analyze requested | %d fixture rules", len(rules))
    return run_pipeline(rules)


# ---------- Phase 1 audit lifecycle -------------------------------------------


def _serialize_run(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in doc.items() if k != "_id"}
    out["id"] = str(doc["_id"])
    for ts_field in ("created_at", "started_at", "completed_at"):
        v = out.get(ts_field)
        if isinstance(v, datetime):
            out[ts_field] = v.isoformat()
    return out


def _serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in doc.items() if k != "_id"}
    if "_id" in doc:
        out["id"] = str(doc["_id"])
    if isinstance(out.get("created_at"), datetime):
        out["created_at"] = out["created_at"].isoformat()
    return out


@app.post("/api/audits", status_code=202)
def create_audit(
    payload: AuditCreateRequest, background_tasks: BackgroundTasks
) -> Dict[str, str]:
    db = db_mod.get_db()
    audit_run_id = audit_mod.create_audit_run(
        db=db,
        account_id=payload.account_id,
        role_arn=payload.role_arn,
        region=payload.region,
        log_window_days=payload.log_window_days,
        seed=False,
    )
    background_tasks.add_task(audit_mod.run_audit_pipeline, audit_run_id, db)
    return {"audit_run_id": audit_run_id, "status": "pending"}


@app.get("/api/audits")
def list_audits() -> List[Dict[str, Any]]:
    db = db_mod.get_db()
    cursor = (
        db["audit_runs"]
        .find({}, {})
        .sort([("created_at", -1), ("_id", -1)])
        .limit(50)
    )
    return [_serialize_run(d) for d in cursor]


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str) -> Dict[str, Any]:
    db = db_mod.get_db()
    doc = db["audit_runs"].find_one({"_id": audit_id})
    if not doc:
        raise HTTPException(status_code=404, detail="audit not found")
    return _serialize_run(doc)


@app.get("/api/audits/{audit_id}/rules")
def get_audit_rules(audit_id: str) -> List[Dict[str, Any]]:
    db = db_mod.get_db()
    cursor = db["rules"].find({"audit_run_id": audit_id})
    return [_serialize_doc(d) for d in cursor]


@app.get("/api/audits/{audit_id}/findings")
def get_audit_findings(audit_id: str) -> List[Dict[str, Any]]:
    db = db_mod.get_db()
    cursor = (
        db["findings"]
        .find({"audit_run_id": audit_id})
        .sort("severity_score", -1)
    )
    return [_serialize_doc(d) for d in cursor]
