"""Audit orchestration worker.

Loads rules (fixture today, real boto3 in Phase 2), runs the two-pass AI
pipeline, computes scoring, and persists everything to Mongo.

The worker function is intentionally a plain function — FastAPI's
BackgroundTasks dispatches it, but tests can call it directly to assert
end-state behavior without a running event loop.
"""
from __future__ import annotations

import json
import logging
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from bson import ObjectId
from pymongo.database import Database

from . import ai_pipeline
from . import scoring

logger = logging.getLogger(__name__)

FIXTURES_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "waf_rules.json"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_audit_run_id() -> str:
    return str(ObjectId())


def load_fixture_rules() -> List[Dict[str, Any]]:
    with FIXTURES_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise RuntimeError("waf_rules.json must be a JSON array")
    return data


def create_audit_run(
    db: Database,
    account_id: str,
    role_arn: str | None,
    region: str,
    log_window_days: int,
    seed: bool = False,
) -> str:
    """Insert an AuditRun in the `pending` state and return its id."""
    audit_run_id = new_audit_run_id()
    db["audit_runs"].insert_one(
        {
            "_id": audit_run_id,
            "account_id": account_id,
            "role_arn": role_arn,
            "region": region,
            "status": "pending",
            "failure_reason": None,
            "created_at": _utcnow(),
            "started_at": None,
            "completed_at": None,
            "web_acl_count": 0,
            "rule_count": 0,
            "log_window_days": log_window_days,
            "estimated_waste_usd": None,
            "seed": seed,
        }
    )
    db["accounts"].update_one(
        {"account_id": account_id},
        {
            "$setOnInsert": {
                "account_id": account_id,
                "role_arn": role_arn,
                "created_at": _utcnow(),
            }
        },
        upsert=True,
    )
    return audit_run_id


def run_audit_pipeline(audit_run_id: str, db: Database) -> None:
    """Execute the audit lifecycle for one AuditRun id.

    Marks the run `running` → `complete`, persisting Rule and Finding docs.
    Any exception sets `failed` with a captured `failure_reason`.
    """
    db["audit_runs"].update_one(
        {"_id": audit_run_id},
        {"$set": {"status": "running", "started_at": _utcnow()}},
    )
    try:
        rules = load_fixture_rules()
        total = len(rules)

        result = ai_pipeline.run_pipeline(rules)
        enriched_rules: List[Dict[str, Any]] = result.get("rules", [])
        findings: List[Dict[str, Any]] = result.get("findings", [])

        rule_docs = []
        web_acls: set = set()
        for r in enriched_rules:
            ai = r.get("ai_explanation") or {}
            rule_docs.append(
                {
                    "audit_run_id": audit_run_id,
                    "web_acl_name": r["web_acl_name"],
                    "rule_name": r["rule_name"],
                    "priority": r["priority"],
                    "action": r["action"],
                    "statement_json": r["statement_json"],
                    "hit_count": r.get("hit_count", 0),
                    "last_fired": r.get("last_fired"),
                    "count_mode_hits": r.get("count_mode_hits", 0),
                    "sample_uris": r.get("sample_uris", []),
                    "fms_managed": r.get("fms_managed", False),
                    "override_action": r.get("override_action"),
                    "ai_explanation": ai.get("explanation"),
                    "ai_working": ai.get("working"),
                    "ai_concerns": ai.get("concerns"),
                }
            )
            web_acls.add(r["web_acl_name"])
        if rule_docs:
            db["rules"].insert_many(rule_docs)

        finding_docs = []
        for f in findings:
            score = scoring.severity_score(
                severity=f.get("severity", "low"),
                confidence=float(f.get("confidence", 0.0)),
                affected_rules=f.get("affected_rules", []),
                total_rule_count=total,
            )
            finding_docs.append(
                {
                    "audit_run_id": audit_run_id,
                    "type": f.get("type"),
                    "severity": f.get("severity"),
                    "title": f.get("title", ""),
                    "description": f.get("description", ""),
                    "recommendation": f.get("recommendation", ""),
                    "affected_rules": f.get("affected_rules", []),
                    "confidence": float(f.get("confidence", 0.0)),
                    "severity_score": score,
                    "created_at": _utcnow(),
                }
            )
        if finding_docs:
            db["findings"].insert_many(finding_docs)

        waste = scoring.estimated_waste_usd(enriched_rules)

        db["audit_runs"].update_one(
            {"_id": audit_run_id},
            {
                "$set": {
                    "status": "complete",
                    "completed_at": _utcnow(),
                    "web_acl_count": len(web_acls),
                    "rule_count": len(rule_docs),
                    "estimated_waste_usd": waste,
                }
            },
        )
        db["accounts"].update_one(
            {
                "account_id": db["audit_runs"]
                .find_one({"_id": audit_run_id}, {"account_id": 1})["account_id"]
            },
            {"$set": {"last_audit_at": _utcnow()}},
        )
        logger.info(
            "Audit %s complete | rules=%d findings=%d waste=$%.2f",
            audit_run_id,
            len(rule_docs),
            len(finding_docs),
            waste,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Audit %s failed: %s\n%s",
            audit_run_id,
            exc,
            traceback.format_exc(),
        )
        db["audit_runs"].update_one(
            {"_id": audit_run_id},
            {
                "$set": {
                    "status": "failed",
                    "failure_reason": str(exc),
                    "completed_at": _utcnow(),
                }
            },
        )
