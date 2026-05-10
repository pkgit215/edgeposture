"""RuleIQ FastAPI application — Phase 2.

Phase 1 endpoints kept; new Phase 2 surface:
    GET  /api/setup-info       — Quick-Create CFN URL + ExternalId + IAM JSON
    POST /api/audits           — accepts optional `external_id`, real or fixture
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from models import AuditCreateRequest
from services import audit as audit_mod
from services import db as db_mod
from services import seed as seed_mod
from services import tenant as tenant_mod
from services.ai_pipeline import run_pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ruleiq")

DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() in ("1", "true", "yes")
TESTING = os.environ.get("RULEIQ_TESTING", "0") == "1"
APP_RUNNER_ACCOUNT_ID = os.environ.get(
    "RULEIQ_APP_RUNNER_ACCOUNT_ID", "371126261144"
)
PUBLIC_TEMPLATES_BUCKET = os.environ.get(
    "RULEIQ_PUBLIC_TEMPLATES_BUCKET",
    f"ruleiq-public-templates-{APP_RUNNER_ACCOUNT_ID}",
)
CFN_TEMPLATE_KEY = "customer-role.yaml"
CFN_TEMPLATE_REGION = "us-east-1"
# SPA dist directory — the multi-stage Dockerfile copies the Vite build here.
# Override via RULEIQ_SPA_DIST for local dev / tests.
SPA_DIST_DIR = Path(
    os.environ.get("RULEIQ_SPA_DIST", "/app/static")
)
logger.info(
    "RuleIQ Phase 3 starting | DEMO_MODE=%s TESTING=%s SPA_DIST=%s",
    DEMO_MODE, TESTING, SPA_DIST_DIR,
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
    description="AI-powered AWS WAF audit tool — Phase 3",
    version="0.4.0",
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
        logger.warning("ensure_demo_seed raised, continuing: %s", exc)


# ---------- Health / OpenAPI -------------------------------------------------


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {
        "status": "ok",
        "phase": "3",
        "mongo": "ok" if db_mod.ping() else "unreachable",
    }


# ---------- Phase 0 back-compat ----------------------------------------------


@app.post("/api/poc/analyze")
def analyze() -> Dict[str, Any]:
    rules = load_fixture_rules()
    logger.info("POC analyze requested | %d fixture rules", len(rules))
    return run_pipeline(rules)


# ---------- Phase 2: setup-info ----------------------------------------------


_INLINE_IAM_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "WAFv2Read",
            "Effect": "Allow",
            "Action": [
                "wafv2:ListWebACLs",
                "wafv2:GetWebACL",
                "wafv2:ListRuleGroups",
                "wafv2:GetRuleGroup",
                "wafv2:GetLoggingConfiguration",
            ],
            "Resource": "*",
        },
        {
            "Sid": "LogsRead",
            "Effect": "Allow",
            "Action": ["logs:DescribeLogGroups", "logs:FilterLogEvents"],
            "Resource": "*",
        },
        {
            "Sid": "S3Read",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": "*",
        },
        {
            "Sid": "FMSRead",
            "Effect": "Allow",
            "Action": ["fms:ListPolicies", "fms:GetPolicy"],
            "Resource": "*",
        },
    ],
}


def _build_quick_create_url(template_url: str, external_id: str) -> str:
    base = (
        "https://console.aws.amazon.com/cloudformation/home"
        "?region=us-east-1#/stacks/quickcreate"
    )
    params = (
        f"templateURL={quote(template_url, safe='')}"
        f"&stackName=RuleIQAuditRole"
        f"&param_RuleIQTrustedAccount={APP_RUNNER_ACCOUNT_ID}"
        f"&param_ExternalId={quote(external_id)}"
    )
    # The fragment after `quickcreate` is the SPA route's own query string —
    # it MUST start with `?`, not `&`. With `&` the console lands on the
    # stacks-list page instead of the Quick-Create form.
    return f"{base}?{params}"


@app.get("/api/setup-info")
def setup_info(account_id: Optional[str] = None) -> Dict[str, Any]:
    """Return onboarding artifacts for the customer's AWS account.

    When `account_id` is missing or invalid, return the IAM policy + null
    ExternalId / null CFN URL so the UI can prompt for the account ID first.
    When valid, derive a deterministic ExternalId via HMAC and bake it into
    the Quick-Create CFN URL.
    """
    template_url = (
        f"https://{PUBLIC_TEMPLATES_BUCKET}.s3.{CFN_TEMPLATE_REGION}.amazonaws.com/"
        f"{CFN_TEMPLATE_KEY}"
    )
    base = {
        "app_runner_account_id": APP_RUNNER_ACCOUNT_ID,
        "cfn_template_url": template_url,
        "inline_iam_json": _INLINE_IAM_POLICY,
        "account_id": account_id,
        "external_id": None,
        "cfn_quick_create_url": None,
    }
    if not account_id or not tenant_mod.is_valid_account_id(account_id):
        return base
    eid = tenant_mod.compute_external_id(account_id)
    base["external_id"] = eid
    base["cfn_quick_create_url"] = _build_quick_create_url(template_url, eid)
    return base


# ---------- Phase 1 audit lifecycle (extended) -------------------------------


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
    # Real-AWS path: re-derive ExternalId server-side from account_id. The
    # client never sends it. Tamper-proof, drift-proof.
    external_id: Optional[str] = None
    if payload.role_arn:
        if not tenant_mod.is_valid_account_id(payload.account_id):
            raise HTTPException(
                status_code=400,
                detail="account_id must be a 12-digit AWS account ID",
            )
        external_id = tenant_mod.compute_external_id(payload.account_id)
    audit_run_id = audit_mod.create_audit_run(
        db=db,
        account_id=payload.account_id,
        role_arn=payload.role_arn,
        region=payload.region,
        log_window_days=payload.log_window_days,
        seed=False,
        external_id=external_id,
    )
    background_tasks.add_task(audit_mod.run_audit_pipeline, audit_run_id, db)
    return {"audit_run_id": audit_run_id, "status": "pending"}


@app.get("/api/audits")
def list_audits() -> List[Dict[str, Any]]:
    db = db_mod.get_db()
    runs = list(
        db["audit_runs"]
        .find({}, {})
        .sort([("created_at", -1), ("_id", -1)])
        .limit(50)
    )
    # One aggregate query for findings_count keyed by audit_run_id (no N+1).
    run_ids = [r["_id"] for r in runs]
    counts: Dict[str, int] = {}
    if run_ids:
        cursor = db["findings"].aggregate(
            [
                {"$match": {"audit_run_id": {"$in": run_ids}}},
                {"$group": {"_id": "$audit_run_id", "n": {"$sum": 1}}},
            ]
        )
        counts = {doc["_id"]: doc["n"] for doc in cursor}
    out: List[Dict[str, Any]] = []
    for r in runs:
        s = _serialize_run(r)
        s["findings_count"] = counts.get(r["_id"], 0)
        out.append(s)
    return out


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str) -> Dict[str, Any]:
    db = db_mod.get_db()
    doc = db["audit_runs"].find_one({"_id": audit_id})
    if not doc:
        raise HTTPException(status_code=404, detail="audit not found")
    out = _serialize_run(doc)
    out["findings_count"] = db["findings"].count_documents(
        {"audit_run_id": audit_id}
    )
    return out


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





# ---------- SPA static mount (Phase 3) ---------------------------------------
# Conditional: only mount when the build directory exists. The multi-stage
# Dockerfile copies the Vite build to /app/static. In local dev the directory
# is absent and the SPA simply isn't served — `/api/*` continues to work.
# IMPORTANT: registered AFTER all `/api/*` routes so they take precedence.


def _mount_spa_if_built(app_: FastAPI, dist_dir: Path) -> None:
    index_path = dist_dir / "index.html"
    if not index_path.is_file():
        logger.info("SPA dist not present at %s — skipping mount", dist_dir)
        return

    assets_dir = dist_dir / "assets"
    if assets_dir.is_dir():
        app_.mount(
            "/assets",
            StaticFiles(directory=str(assets_dir)),
            name="spa-assets",
        )

    @app_.get("/", include_in_schema=False)
    def _spa_root() -> FileResponse:  # noqa: D401
        return FileResponse(str(index_path))

    @app_.get("/{full_path:path}", include_in_schema=False)
    def _spa_catchall(full_path: str) -> FileResponse:
        # Never shadow API routes; FastAPI matches `/api/*` first because they
        # were registered above this catch-all.
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404)
        candidate = dist_dir / full_path
        if candidate.is_file():
            return FileResponse(str(candidate))
        # SPA fallback — serve index.html so client-side state navigation works
        # on direct URL hits / refresh.
        return FileResponse(str(index_path))

    logger.info("SPA mounted from %s", dist_dir)


_mount_spa_if_built(app, SPA_DIST_DIR)

