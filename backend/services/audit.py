"""Audit orchestration worker — Phase 2.

Hybrid switch:
    DEMO_MODE=true OR no role_arn  → fixture path (Phase 1 behavior)
    Otherwise                       → real AWS reads via aws_waf module
"""
from __future__ import annotations

import json
import logging
import os
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from bson import ObjectId
from pymongo.database import Database

from . import ai_pipeline
from . import aws_waf
from . import scoring

logger = logging.getLogger(__name__)

FIXTURES_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "waf_rules.json"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_audit_run_id() -> str:
    return str(ObjectId())


def _demo_mode() -> bool:
    return os.environ.get("DEMO_MODE", "false").lower() in ("1", "true", "yes")


def load_fixture_rules() -> List[Dict[str, Any]]:
    with FIXTURES_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise RuntimeError("waf_rules.json must be a JSON array")
    return data


def create_audit_run(
    db: Database,
    account_id: str,
    role_arn: Optional[str],
    region: str,
    log_window_days: int,
    seed: bool = False,
    external_id: Optional[str] = None,
) -> str:
    audit_run_id = new_audit_run_id()
    db["audit_runs"].insert_one(
        {
            "_id": audit_run_id,
            "account_id": account_id,
            "role_arn": role_arn,
            "external_id": external_id,
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
            "estimated_waste_breakdown": None,
            "fms_visibility": None,
            "logging_available": None,
            "data_source": "pending",
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


# ---------- Source loaders ---------------------------------------------------


def _load_rules_from_fixtures() -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    rules = load_fixture_rules()
    meta = {
        "data_source": "fixture",
        "fms_visibility": None,
        "logging_available": True,
        "web_acl_count": len({r["web_acl_name"] for r in rules}),
    }
    return rules, meta


def _load_rules_from_aws(
    account_id: str,
    role_arn: str,
    region: str,
    external_id: Optional[str],
    log_window_days: int,
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    session = aws_waf.assume_role(role_arn, external_id)
    web_acls = aws_waf.list_web_acls(session, region)
    fms_info = aws_waf.enrich_fms(session, account_id, region)

    rules: List[Dict[str, Any]] = []
    any_logging = False
    for acl in web_acls:
        log_group = aws_waf.discover_logging(session, acl["ARN"])
        if log_group:
            any_logging = True
        for rule in aws_waf.get_web_acl_rules(session, acl):
            if log_group:
                stats = aws_waf.get_rule_stats(
                    session,
                    log_group,
                    rule["rule_name"],
                    acl["Name"],
                    days=log_window_days,
                )
            else:
                stats = {
                    "hit_count": 0,
                    "last_fired": None,
                    "count_mode_hits": 0,
                    "sample_uris": [],
                }
            rules.append(
                {
                    **rule,
                    **stats,
                    "web_acl_name": acl["Name"],
                }
            )
    meta = {
        "data_source": "aws",
        "fms_visibility": bool(fms_info.get("available")),
        "logging_available": any_logging,
        "web_acl_count": len(web_acls),
    }
    return rules, meta


# ---------- Worker -----------------------------------------------------------


def run_audit_pipeline(audit_run_id: str, db: Database) -> None:
    """Execute the audit lifecycle for one AuditRun id."""
    db["audit_runs"].update_one(
        {"_id": audit_run_id},
        {"$set": {"status": "running", "started_at": _utcnow()}},
    )
    try:
        run = db["audit_runs"].find_one({"_id": audit_run_id})
        if not run:
            raise RuntimeError(f"audit_run {audit_run_id} disappeared")

        role_arn = run.get("role_arn")
        if _demo_mode() or not role_arn:
            # Set data_source FIRST so a failure mid-load still reports correctly.
            db["audit_runs"].update_one(
                {"_id": audit_run_id}, {"$set": {"data_source": "fixture"}}
            )
            rules, meta = _load_rules_from_fixtures()
        else:
            db["audit_runs"].update_one(
                {"_id": audit_run_id}, {"$set": {"data_source": "aws"}}
            )
            rules, meta = _load_rules_from_aws(
                account_id=run["account_id"],
                role_arn=role_arn,
                region=run.get("region", "us-east-1"),
                external_id=run.get("external_id"),
                log_window_days=run.get("log_window_days", 30),
            )

        if not rules:
            db["audit_runs"].update_one(
                {"_id": audit_run_id},
                {
                    "$set": {
                        "status": "complete",
                        "completed_at": _utcnow(),
                        "rule_count": 0,
                        "web_acl_count": meta.get("web_acl_count", 0),
                        "fms_visibility": meta.get("fms_visibility"),
                        "logging_available": meta.get("logging_available"),
                        "data_source": meta.get("data_source"),
                        "estimated_waste_usd": 0.0,
                        "estimated_waste_breakdown": [],
                        "failure_reason": (
                            f"No Web ACLs found in scope "
                            f"region={run.get('region')} account={run['account_id']}"
                        ),
                    }
                },
            )
            return

        result = ai_pipeline.run_pipeline(rules)
        enriched_rules: List[Dict[str, Any]] = result.get("rules", [])
        findings: List[Dict[str, Any]] = result.get("findings", [])
        total = len(enriched_rules)

        rule_docs: List[Dict[str, Any]] = []
        web_acls: set = set()
        for r in enriched_rules:
            ai = r.get("ai_explanation") or {}
            rule_docs.append(
                {
                    "audit_run_id": audit_run_id,
                    "web_acl_name": r["web_acl_name"],
                    "rule_name": r["rule_name"],
                    "priority": r.get("priority", 0),
                    "action": r.get("action", "ALLOW"),
                    "statement_json": r.get("statement_json", {}),
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

        finding_docs: List[Dict[str, Any]] = []
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
        breakdown = scoring.estimated_waste_breakdown(enriched_rules)

        db["audit_runs"].update_one(
            {"_id": audit_run_id},
            {
                "$set": {
                    "status": "complete",
                    "completed_at": _utcnow(),
                    "web_acl_count": meta.get("web_acl_count", len(web_acls)),
                    "rule_count": len(rule_docs),
                    "estimated_waste_usd": waste,
                    "estimated_waste_breakdown": breakdown,
                    "fms_visibility": meta.get("fms_visibility"),
                    "logging_available": meta.get("logging_available"),
                    "data_source": meta.get("data_source"),
                }
            },
        )
        db["accounts"].update_one(
            {"account_id": run["account_id"]},
            {"$set": {"last_audit_at": _utcnow()}},
        )
        logger.info(
            "Audit %s complete | source=%s rules=%d findings=%d waste=$%.2f",
            audit_run_id,
            meta.get("data_source"),
            len(rule_docs),
            len(finding_docs),
            waste,
        )
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if "AccessDenied" in msg or "AssumeRole" in msg or "sts" in msg.lower():
            failure = f"AssumeRole denied: {msg}"
        else:
            failure = msg
        logger.error(
            "Audit %s failed: %s\n%s",
            audit_run_id,
            failure,
            traceback.format_exc(),
        )
        db["audit_runs"].update_one(
            {"_id": audit_run_id},
            {
                "$set": {
                    "status": "failed",
                    "failure_reason": failure,
                    "completed_at": _utcnow(),
                }
            },
        )
