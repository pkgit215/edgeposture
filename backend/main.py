"""EdgePosture FastAPI application — Phase 2.

Phase 1 endpoints kept; new Phase 2 surface:
    GET  /api/setup-info       — Quick-Create CFN URL + ExternalId + IAM JSON
    POST /api/audits           — accepts optional `external_id`, real or fixture
"""
from __future__ import annotations

import functools
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from models import AuditCreateRequest
from services import audit as audit_mod
from services import db as db_mod
from services import pdf_report as pdf_mod
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
    "RULEIQ_APP_RUNNER_ACCOUNT_ID", "123456789012"
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
    "EdgePosture Phase 3 starting | DEMO_MODE=%s TESTING=%s SPA_DIST=%s",
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
    title="EdgePosture",
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
        "phase": "5.3.2",
        "mongo": "ok" if db_mod.ping() else "unreachable",
    }


@app.get("/api/debug/last-audit")
def debug_last_audit() -> Dict[str, Any]:
    """Phase 5.2.1 debug endpoint — returns the most recent AWS-path audit
    run document for diagnostics. NO AUTH. GET only. Read-only.

    Removes ObjectIds + bytes; truncates suspicious_request_sample to 3
    entries to keep response under a few KB. Intentionally exposes web_acls
    in full so attachment status (attached / attached_resources) is
    inspectable from outside the pod via curl.
    """
    try:
        database = db_mod.get_db()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"mongo_unreachable: {exc}"}
    doc = database["audit_runs"].find_one(
        {"data_source": "aws"}, sort=[("created_at", -1)]
    )
    if not doc:
        return {"error": "no_aws_audit_found"}

    def _scrub(o: Any) -> Any:
        if isinstance(o, bytes):
            try:
                return o.decode("utf-8", errors="replace")
            except Exception:
                return f"<{len(o)} bytes>"
        if isinstance(o, dict):
            return {k: _scrub(v) for k, v in o.items() if k != "_id" or True}
        if isinstance(o, list):
            return [_scrub(x) for x in o]
        if hasattr(o, "isoformat"):
            try:
                return o.isoformat()
            except Exception:
                return str(o)
        return o

    out = _scrub(doc)
    # Cap noisy fields so the response is curl-friendly.
    if isinstance(out.get("suspicious_request_sample"), list):
        out["suspicious_request_sample"] = out["suspicious_request_sample"][:3]
    if isinstance(out.get("debug_log_sample"), list):
        out["debug_log_sample"] = out["debug_log_sample"][:3]
    return out


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
        f"&stackName=EdgePostureAuditRole"
        f"&param_EdgePostureTrustedAccount={APP_RUNNER_ACCOUNT_ID}"
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


def _utc_iso(d: Any) -> Any:
    """Phase 5.2.2 — emit an unambiguous UTC ISO string with a 'Z' suffix.

    pymongo returns BSON Date as tz-naive Python datetime; calling
    `.isoformat()` on that produces `'2026-05-11T14:01:50.651000'` with no
    offset. JS `new Date()` then interprets that as LOCAL time, displaying
    timestamps off by the local UTC offset (the user's "4 hours ahead"
    report). Force UTC interpretation at the serialization boundary.
    """
    if not isinstance(d, datetime):
        return d
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    else:
        d = d.astimezone(timezone.utc)
    return d.isoformat().replace("+00:00", "Z")


def _serialize_run(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in doc.items() if k != "_id"}
    out["id"] = str(doc["_id"])
    for ts_field in ("created_at", "started_at", "completed_at"):
        if ts_field in out:
            out[ts_field] = _utc_iso(out[ts_field])
    return out


def _serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in doc.items() if k != "_id"}
    if "_id" in doc:
        out["id"] = str(doc["_id"])
    if "created_at" in out:
        out["created_at"] = _utc_iso(out["created_at"])
    return out


def _upsert_account(db: Any, account_id: str, role_arn: Optional[str]) -> None:
    """Phase 4.5 — DEPRECATED at v4.5.1. Account upsert is now canonical
    inside `audit.create_audit_run` so the same `$set last_audit_at`
    semantics apply on both `/api/audits` and `/api/audits/rerun` without
    duplication. This wrapper is kept as a safety belt: if `audit.py` is
    later refactored, the explicit call site in `create_audit` still
    advances `last_audit_at`. Best-effort, never blocks."""
    if not role_arn or not tenant_mod.is_valid_account_id(account_id):
        return
    try:
        now = datetime.now(timezone.utc)
        db["accounts"].update_one(
            {"account_id": account_id},
            {
                "$set": {
                    "role_arn": role_arn,
                    "last_audit_at": now,
                },
                "$setOnInsert": {
                    "account_id": account_id,
                    "created_at": now,
                },
            },
            upsert=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("accounts upsert failed (account=%s): %s", account_id, exc)


def _serialize_account(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "account_id": doc.get("account_id"),
        "role_arn": doc.get("role_arn"),
        "created_at": _utc_iso(doc.get("created_at")),
        "last_audit_at": _utc_iso(doc.get("last_audit_at")),
    }


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
    _upsert_account(db, payload.account_id, payload.role_arn)
    background_tasks.add_task(audit_mod.run_audit_pipeline, audit_run_id, db)
    return {"audit_run_id": audit_run_id, "status": "pending"}


# ---- Phase 4.5 account memory + re-run ------------------------------------


class AuditRerunRequest(BaseModel):
    account_id: str = Field(min_length=12, max_length=12)
    region: str = "us-east-1"


@app.post("/api/audits/rerun", status_code=202)
def rerun_audit(
    payload: AuditRerunRequest, background_tasks: BackgroundTasks
) -> Dict[str, str]:
    if not tenant_mod.is_valid_account_id(payload.account_id):
        raise HTTPException(
            status_code=400,
            detail="account_id must be a 12-digit AWS account ID",
        )
    db = db_mod.get_db()
    acc = db["accounts"].find_one({"account_id": payload.account_id})
    if not acc or not acc.get("role_arn"):
        return Response(
            content=json.dumps(
                {
                    "error": "No saved role for this account. "
                    "Use /api/audits with a role_arn."
                }
            ),
            status_code=404,
            media_type="application/json",
        )
    role_arn = acc["role_arn"]
    external_id = tenant_mod.compute_external_id(payload.account_id)
    audit_run_id = audit_mod.create_audit_run(
        db=db,
        account_id=payload.account_id,
        role_arn=role_arn,
        region=payload.region,
        log_window_days=30,
        seed=False,
        external_id=external_id,
    )
    _upsert_account(db, payload.account_id, role_arn)
    background_tasks.add_task(audit_mod.run_audit_pipeline, audit_run_id, db)
    return {"audit_run_id": audit_run_id, "status": "pending"}


@app.get("/api/accounts")
def list_accounts() -> List[Dict[str, Any]]:
    db = db_mod.get_db()
    cursor = (
        db["accounts"]
        .find({}, {})
        .sort([("last_audit_at", -1)])
    )
    out = []
    for doc in cursor:
        s = _serialize_account(doc)
        # List view drops created_at to keep the response small.
        out.append(
            {
                "account_id": s["account_id"],
                "role_arn": s["role_arn"],
                "last_audit_at": s["last_audit_at"],
            }
        )
    return out


@app.get("/api/accounts/{account_id}")
def get_account(account_id: str) -> Dict[str, Any]:
    if not tenant_mod.is_valid_account_id(account_id):
        raise HTTPException(
            status_code=422, detail="account_id must be a 12-digit AWS account ID"
        )
    db = db_mod.get_db()
    doc = db["accounts"].find_one({"account_id": account_id})
    if not doc:
        raise HTTPException(status_code=404, detail="account not found")
    return _serialize_account(doc)


# --- Issue #22 — public demo fixture ---------------------------------------

_DEMO_FIXTURE_DIR = Path(__file__).resolve().parent / "demo"


@functools.lru_cache(maxsize=1)
def _load_demo_audit() -> Dict[str, Any]:
    """Load + cache the committed demo fixture JSON."""
    p = _DEMO_FIXTURE_DIR / "demo_audit.json"
    if not p.exists():
        raise HTTPException(status_code=503, detail="demo fixture not present")
    return json.loads(p.read_text())


@app.get("/api/demo/audit")
def get_demo_audit() -> Dict[str, Any]:
    """Pre-canned demo audit — combined `{audit, rules, findings}` payload.
    Public, no auth, no role assumption. Source: backend/demo/demo_audit.json."""
    return _load_demo_audit()


@app.get("/api/demo/report.pdf")
def get_demo_report_pdf() -> Response:
    """Pre-rendered demo PDF served as static bytes."""
    p = _DEMO_FIXTURE_DIR / "demo_audit.pdf"
    if not p.exists():
        raise HTTPException(status_code=503, detail="demo PDF not present")
    return Response(
        content=p.read_bytes(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'inline; filename="edgeposture-demo-audit.pdf"',
        },
    )



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


@app.get("/api/audits/{audit_id}/report.pdf")
def get_audit_report_pdf(audit_id: str) -> Response:
    """Phase 4 — render the executive PDF report for a complete audit run."""
    db = db_mod.get_db()
    run = db["audit_runs"].find_one({"_id": audit_id})
    if not run:
        raise HTTPException(status_code=404, detail="audit not found")
    status = run.get("status")
    if status != "complete":
        return Response(
            content=json.dumps(
                {"error": "Audit not yet complete", "status": status}
            ),
            status_code=409,
            media_type="application/json",
        )
    rules = list(
        db["rules"]
        .find({"audit_run_id": audit_id})
        .sort([("web_acl_name", 1), ("priority", 1)])
    )
    findings = list(
        db["findings"]
        .find({"audit_run_id": audit_id})
        .sort("severity_score", -1)
    )
    pdf_bytes = pdf_mod.render_audit_pdf(run, rules, findings)
    completed = run.get("completed_at") or run.get("created_at")
    if isinstance(completed, datetime):
        ymd = completed.strftime("%Y%m%d")
    else:
        ymd = datetime.now().strftime("%Y%m%d")
    account = run.get("account_id") or "unknown"
    filename = f"edgeposture-audit-{account}-{ymd}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )







# ---------- SPA static mount (Phase 3) ---------------------------------------
# Conditional: only mount when the build directory exists. The multi-stage
# Dockerfile copies the Vite build to /app/static. In local dev the directory
# is absent and the SPA simply isn't served — `/api/*` continues to work.
# IMPORTANT: registered AFTER all `/api/*` routes so they take precedence.
#
# Fix #28 — cache headers:
#   * index.html is served with `Cache-Control: no-cache, must-revalidate`
#     (plus Pragma + Expires for old proxies). Vite hashes asset filenames
#     per build, so index.html is the ONLY artefact whose contents change
#     under a stable URL — caching it means users keep loading deleted
#     hashed bundles after a deploy.
#   * Hashed assets under /assets/* are immutable: `Cache-Control:
#     public, max-age=31536000, immutable`. The filename changes whenever
#     contents change, so aggressive caching is correct.

_INDEX_NO_CACHE_HEADERS: Dict[str, str] = {
    "Cache-Control": "no-cache, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}
_ASSET_IMMUTABLE_HEADERS: Dict[str, str] = {
    "Cache-Control": "public, max-age=31536000, immutable",
}


class _ImmutableAssetsStaticFiles(StaticFiles):
    """StaticFiles subclass that stamps long-cache headers on every file.

    Used only for `/assets/*`, where Vite emits hash-named bundles
    (`index-abc123.js`). Filenames change whenever contents change, so
    1-year immutable caching is the correct trade-off."""

    async def get_response(self, path: str, scope):  # type: ignore[override]
        resp = await super().get_response(path, scope)
        if resp.status_code == 200:
            for k, v in _ASSET_IMMUTABLE_HEADERS.items():
                resp.headers[k] = v
        return resp


def _mount_spa_if_built(app_: FastAPI, dist_dir: Path) -> None:
    index_path = dist_dir / "index.html"
    if not index_path.is_file():
        logger.info("SPA dist not present at %s — skipping mount", dist_dir)
        return

    assets_dir = dist_dir / "assets"
    if assets_dir.is_dir():
        app_.mount(
            "/assets",
            _ImmutableAssetsStaticFiles(directory=str(assets_dir)),
            name="spa-assets",
        )

    def _index_response() -> FileResponse:
        return FileResponse(str(index_path), headers=_INDEX_NO_CACHE_HEADERS)

    @app_.get("/", include_in_schema=False)
    def _spa_root() -> FileResponse:  # noqa: D401
        return _index_response()

    @app_.get("/{full_path:path}", include_in_schema=False)
    def _spa_catchall(full_path: str) -> FileResponse:
        # Never shadow API routes; FastAPI matches `/api/*` first because they
        # were registered above this catch-all.
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404)
        candidate = dist_dir / full_path
        if candidate.is_file():
            # Non-asset top-level files (favicon, robots.txt, etc.) — short
            # cache, not immutable, since their filenames don't change.
            return FileResponse(str(candidate))
        # SPA fallback — serve index.html so client-side state navigation works
        # on direct URL hits / refresh. MUST carry no-cache headers so that
        # /demo, /connect, /history etc. always pick up the latest bundle.
        return _index_response()

    logger.info("SPA mounted from %s", dist_dir)


_mount_spa_if_built(app, SPA_DIST_DIR)

