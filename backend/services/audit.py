"""Audit orchestration worker.

Hybrid switch:
    DEMO_MODE=true OR no role_arn  → fixture path (Phase 1 behaviour)
    Otherwise                       → real AWS reads via aws_waf module

Phase 5 changes
---------------
* Stamps `rule_kind` on every rule (custom | managed | rate_based) so
  `scoring.kind_severity()` can downgrade noise findings.
* Calls `wafv2:list-resources-for-web-acl` for each Web ACL and persists
  the result as `audit_run.web_acls`. ACLs with zero attached resources are
  treated as *orphaned* — any `dead_rule` finding referencing only orphan-
  ACL rules is suppressed and replaced with a single `orphaned_web_acl`
  finding per orphaned ACL.
* Persists `evidence` on findings produced by Pass-3 bypass detection.
* Cross-checks the model's Pass-2 output: any finding whose entire
  `affected_rules` set is FMS-managed or managed rule groups is forced to
  severity='low' and re-typed to `fms_review` if it was dead_rule/quick_win
  (defence-in-depth — the model is instructed but not relied upon).
"""
from __future__ import annotations

import json
import logging
import os
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from bson import ObjectId
from pymongo.database import Database

from . import ai_pipeline
from . import aws_waf
from . import scoring

logger = logging.getLogger(__name__)

FIXTURES_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "waf_rules.json"

# Phase 5 — rule types that "delete or consolidate this rule" recommendations
# apply to. We never produce these for FMS-managed, managed-rule-group, or
# orphan-ACL rules.
_REMOVAL_FINDING_TYPES = {"dead_rule", "quick_win"}


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
            "web_acls": None,
        }
    )
    db["accounts"].update_one(
        {"account_id": account_id},
        {
            "$set": {
                "role_arn": role_arn,
                "last_audit_at": _utcnow(),
            },
            "$setOnInsert": {
                "account_id": account_id,
                "created_at": _utcnow(),
            },
        },
        upsert=True,
    )
    return audit_run_id


# ---------- Source loaders ---------------------------------------------------


def _load_rules_from_fixtures() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    rules = load_fixture_rules()
    # Phase 5 — fixtures predate `rule_kind`, derive it from the statement.
    for r in rules:
        if "rule_kind" not in r:
            r["rule_kind"] = aws_waf.classify_rule_kind(
                r.get("statement_json") or {}
            )
    acl_names = sorted({r["web_acl_name"] for r in rules})
    web_acls = [
        {
            "name": name,
            "scope": "REGIONAL",
            "arn": None,
            "attached_resources": ["demo://attached"],
            "attached": True,
        }
        for name in acl_names
    ]
    meta = {
        "data_source": "fixture",
        "fms_visibility": None,
        "logging_available": True,
        "web_acl_count": len(acl_names),
        "web_acls": web_acls,
        "orphan_acl_names": set(),
        "suspicious_requests": [],
    }
    return rules, meta


def _load_rules_from_aws(
    account_id: str,
    role_arn: str,
    region: str,
    external_id: Optional[str],
    log_window_days: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    session = aws_waf.assume_role(role_arn, external_id)
    web_acls = aws_waf.list_web_acls(session, region)
    fms_info = aws_waf.enrich_fms(session, account_id, region)

    rules: List[Dict[str, Any]] = []
    any_logging = False
    web_acl_summaries: List[Dict[str, Any]] = []
    orphan_acl_names: set = set()
    per_acl_samples: List[List[Dict[str, Any]]] = []
    debug_log_sample: List[Dict[str, Any]] = []
    scopes_seen: set = set()

    for acl in web_acls:
        scopes_seen.add(acl.get("Scope", "REGIONAL"))
        # Phase 5 — attachment check first.
        # Production fix: list_resources_for_web_acl now returns None when
        # the call AccessDenied'd or the CloudFront scope returned its
        # unreliable empty. None → "unknown" attachment, NOT orphan.
        attached_resources = aws_waf.list_resources_for_web_acl(session, acl)
        # Phase 5.2.2 — for CLOUDFRONT we also have the list-distributions
        # payload, which carries DomainName. Re-fetch to feed
        # friendly-name enrichment with the richer hint.
        cf_distros_hint = None
        if acl.get("Scope") == "CLOUDFRONT":
            cf_distros_hint = aws_waf.list_cloudfront_distributions_for_web_acl(
                session, acl["ARN"]
            )
        if attached_resources is None:
            attached_resources_list: List[Any] = []
            attached: Optional[bool] = None  # unknown
        else:
            attached_resources_list = aws_waf.enrich_resource_friendly_names(
                session, list(attached_resources), cf_distros=cf_distros_hint
            )
            attached = bool(attached_resources_list)
        web_acl_summaries.append(
            {
                "name": acl["Name"],
                "scope": acl.get("Scope", "REGIONAL"),
                "arn": acl.get("ARN"),
                "attached_resources": attached_resources_list,
                "attached": attached,
            }
        )
        if attached is False:  # explicit orphan only — not None
            orphan_acl_names.add(acl["Name"])

        log_group = aws_waf.discover_logging(session, acl["ARN"])
        if log_group:
            any_logging = True
            # Phase 5.5 — sample ALLOW traffic globally for bypass detection.
            # ONE additional CloudWatch query per Web ACL (server-filtered to
            # ALLOW, so it doesn't drag back the BLOCK volume we already
            # fetched per-rule). The result is fed into Pass 3.
            try:
                acl_debug: List[Dict[str, Any]] = []
                sample = aws_waf.sample_suspicious_allowed_requests(
                    session, log_group, days=log_window_days, top_k=50,
                    debug_capture=acl_debug,
                )
                # Phase 5 production fix: keep first 5 raw events for the
                # audit run doc so an operator can verify the production
                # log shape matches expectations.
                if acl_debug and len(debug_log_sample) < 5:
                    for ev in acl_debug:
                        if len(debug_log_sample) >= 5:
                            break
                        debug_log_sample.append({
                            "web_acl": acl["Name"],
                            "log_group_arn": log_group,
                            "event": ev,
                        })
                if sample:
                    per_acl_samples.append(sample)
                logger.info(
                    "Bypass sampler | acl=%s log_group=%s "
                    "events_seen_in_debug=%d suspicious_kept=%d",
                    acl["Name"], log_group, len(acl_debug), len(sample),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "ALLOW-traffic sampling failed for %s: %s — Pass 3 will run"
                    " against the surviving per-ACL samples.",
                    acl["Name"],
                    exc,
                )
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

    # Phase 5.5 — merge per-ACL top-50 samples into a global top-50.
    suspicious_requests = aws_waf.merge_suspicious_samples(
        per_acl_samples, top_k=50
    )

    meta = {
        "data_source": "aws",
        "fms_visibility": bool(fms_info.get("available")),
        "logging_available": any_logging,
        "web_acl_count": len(web_acls),
        "web_acls": web_acl_summaries,
        "orphan_acl_names": orphan_acl_names,
        "suspicious_requests": suspicious_requests,
        "debug_log_sample": debug_log_sample,
        "scopes": sorted(scopes_seen),
    }
    return rules, meta


# ---------- Finding post-processing (Phase 5) --------------------------------


def _is_protected_rule(rule: Dict[str, Any]) -> bool:
    """Rules that should NEVER appear in a removal-type finding."""
    if rule.get("fms_managed"):
        return True
    if (rule.get("rule_kind") or "custom") == "managed":
        return True
    return False


def _resource_aware_duplicate_findings(
    findings: List[Dict[str, Any]],
    rules_by_name: Dict[str, Dict[str, Any]],
    rules_by_acl: Dict[str, List[Dict[str, Any]]],
    acl_summaries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Phase 5.2 — replace naive name-based duplicate findings with
    resource-aware logic.

    Phase 5.2.2 — broadened to also process findings of type
    `rule_conflict`, `duplicate_rule`, and `conflict` (Pass-2 GPT may
    emit any of these for cross-ACL same-name rules; the previous
    implementation only processed `quick_win` and missed them all).

    For each finding listing multiple rules with the SAME name (or
    substantially overlapping statement_json), determine the relationship
    between the parent Web ACLs' attached resources:

      * Same resource ARN in both ACLs → REAL duplicate, severity LOW,
        evidence='shared_resource'.
      * Both ACLs attached to entirely different resources → SUPPRESS.
        These are intentional "consistent policy" replicas.
      * One ACL orphan, one attached → "stranded rule" finding, LOW,
        evidence='stranded'.
      * Either ACL's attachment unknown → low-confidence "verify" finding,
        LOW, evidence='unverified', confidence=0.5.
    """
    DUPLICATE_TYPES = {"quick_win", "rule_conflict", "duplicate_rule", "conflict"}
    by_acl_name_to_summary: Dict[str, Dict[str, Any]] = {
        a["name"]: a for a in acl_summaries
    }
    out: List[Dict[str, Any]] = []
    for f in findings:
        ftype = f.get("type")
        if ftype not in DUPLICATE_TYPES:
            out.append(f)
            continue
        affected_names = list(f.get("affected_rules") or [])
        # Group rules by their (rule_name) and observe their parent ACLs.
        rules_in_finding = [rules_by_name[n] for n in affected_names if n in rules_by_name]
        if len(rules_in_finding) < 2:
            out.append(f)
            continue
        # Look for any sub-pair that share the same rule_name across ACLs.
        name_to_acl: Dict[str, List[str]] = {}
        for r in rules_in_finding:
            name_to_acl.setdefault(r["rule_name"], []).append(r["web_acl_name"])
        cross_acl_groups = {
            name: sorted(set(acls))
            for name, acls in name_to_acl.items()
            if len(set(acls)) >= 2
        }
        if not cross_acl_groups:
            # Single-ACL quick_win — pass through unchanged.
            out.append(f)
            continue

        def _arns_of(summary: Dict[str, Any]) -> set:
            """Phase 5.2.2 — `attached_resources` is now a list of
            `{arn,type,id,friendly}` dicts (post-friendly-name enrichment).
            Earlier code stored bare ARN strings. Accept both shapes."""
            out = set()
            for item in (summary.get("attached_resources") or []):
                if isinstance(item, dict):
                    v = item.get("arn")
                    if v:
                        out.add(v)
                elif isinstance(item, str) and item:
                    out.add(item)
            return out

        new_findings_for_pair: List[Dict[str, Any]] = []
        for rule_name, acl_names in cross_acl_groups.items():
            summaries = [by_acl_name_to_summary.get(n) or {} for n in acl_names]
            resources_per_acl = [_arns_of(s) for s in summaries]
            attached_flags = [s.get("attached") for s in summaries]
            unknown = any(a is None for a in attached_flags)
            both_attached = all(a is True for a in attached_flags)
            any_orphan = any(a is False for a in attached_flags)
            shared = set.intersection(*resources_per_acl) if resources_per_acl else set()
            base = {
                "affected_rules": [rule_name],
                "confidence": float(f.get("confidence") or 0.7),
            }
            if both_attached and shared:
                new_findings_for_pair.append({
                    **base,
                    "type": "quick_win",
                    "severity": "low",
                    "title": f"Duplicate rule '{rule_name}' across ACLs sharing a resource",
                    "description": (
                        f"Rule '{rule_name}' appears in ACLs {acl_names}, both "
                        f"attached to overlapping resource(s): {sorted(shared)}. "
                        "This is a real anti-pattern — consolidate into one ACL."
                    ),
                    "recommendation": (
                        "Remove the duplicate from one ACL; pick the ACL whose "
                        "rule set is most appropriate for the shared resource."
                    ),
                    "evidence": "shared_resource",
                })
            elif both_attached and not shared:
                logger.info(
                    "Suppressing duplicate finding for %r — ACLs %s protect "
                    "DIFFERENT resources, not a real duplicate.",
                    rule_name, acl_names,
                )
                # NOT a duplicate — intentional consistent policy across
                # different resources. Suppressed.
                continue
            elif any_orphan and not all(a is False for a in attached_flags):
                orphan_acls = [n for n, a in zip(acl_names, attached_flags) if a is False]
                new_findings_for_pair.append({
                    **base,
                    "type": "quick_win",
                    "severity": "low",
                    "title": f"Stranded rule '{rule_name}' in orphaned ACL",
                    "description": (
                        f"Rule '{rule_name}' is duplicated in orphan ACL(s) "
                        f"{orphan_acls} as well as attached ACL(s). The orphan "
                        "copy protects nothing."
                    ),
                    "recommendation": (
                        "Either attach the orphan ACL or delete it. Either "
                        "way the duplicate rule should be consolidated."
                    ),
                    "evidence": "stranded",
                })
            elif unknown:
                new_findings_for_pair.append({
                    **base,
                    "type": "quick_win",
                    "severity": "low",
                    "title": f"Potential duplicate rule '{rule_name}' (attachment unverified)",
                    "description": (
                        f"Rule '{rule_name}' appears in ACLs {acl_names}, but "
                        "attachment status of one or both could not be "
                        "verified (IAM permission or API limitation)."
                    ),
                    "recommendation": (
                        "Grant cloudfront:ListDistributions and "
                        "wafv2:ListResourcesForWebACL to the audit role and "
                        "re-run to confirm whether this is a real duplicate."
                    ),
                    "confidence": 0.5,
                    "evidence": "unverified",
                })
            else:
                # Both orphan — let the orphaned_web_acl findings cover it;
                # no separate duplicate emission needed.
                logger.info(
                    "Both ACLs in finding %r are orphaned — suppressing "
                    "duplicate, covered by orphan findings.", rule_name,
                )
        if new_findings_for_pair:
            out.extend(new_findings_for_pair)
        # If we re-emitted no findings (all suppressed), drop the original.
    return out


def _apply_phase5_finding_guardrails(
    findings: List[Dict[str, Any]],
    rules_by_name: Dict[str, Dict[str, Any]],
    orphan_acl_names: set,
) -> List[Dict[str, Any]]:
    """Defence-in-depth filtering of LLM Pass-2 output.

    1. Drop `dead_rule`/`quick_win` findings whose entire `affected_rules`
       set is in an orphaned Web ACL.
    2. Re-type any `dead_rule`/`quick_win` finding whose affected rules are
       *all* protected (FMS or managed group) into `fms_review` low.
    3. Force severity='low' for findings of `type='fms_review'`.
    """
    out: List[Dict[str, Any]] = []
    for f in findings:
        ftype = f.get("type")
        affected: List[str] = list(f.get("affected_rules") or [])
        affected_rules = [
            rules_by_name[name] for name in affected if name in rules_by_name
        ]
        if ftype in _REMOVAL_FINDING_TYPES and affected_rules:
            # Orphan-ACL suppression
            if all(
                r.get("web_acl_name") in orphan_acl_names for r in affected_rules
            ):
                logger.info(
                    "Suppressing %s finding %r — all affected rules in orphaned ACL",
                    ftype,
                    f.get("title"),
                )
                continue
            # Managed/FMS re-typing
            if all(_is_protected_rule(r) for r in affected_rules):
                f = {
                    **f,
                    "type": "fms_review",
                    "severity": "low",
                    "recommendation": (
                        f.get("recommendation")
                        or "Managed/FMS rule — flag for central security review."
                    ),
                }
        if f.get("type") == "fms_review":
            f["severity"] = "low"
        out.append(f)
    return out


def _orphaned_acl_findings(
    web_acl_summaries: List[Dict[str, Any]],
    rules_by_acl: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """One `orphaned_web_acl` finding per orphaned ACL.

    Production fix: only emit when `attached is False` *explicitly*.
    `attached is None` means status is unknown (AccessDenied / CloudFront
    unreliable) and MUST NOT produce a false-positive orphan finding.
    """
    out: List[Dict[str, Any]] = []
    for acl in web_acl_summaries:
        if acl.get("attached") is not False:
            continue
        acl_name = acl["name"]
        rule_names = [r["rule_name"] for r in rules_by_acl.get(acl_name, [])]
        out.append(
            {
                "type": "orphaned_web_acl",
                "severity": "low",
                "title": f"Web ACL '{acl_name}' is not attached to any resource",
                "description": (
                    f"This Web ACL ({acl.get('scope', 'REGIONAL')}) has zero "
                    "associated resources (ALB / API Gateway / AppSync / "
                    "CloudFront). All its rules are dormant by definition."
                ),
                "recommendation": (
                    "Either attach the ACL to an in-use resource or delete it. "
                    "Web ACLs incur a fixed monthly fee regardless of traffic."
                ),
                "affected_rules": rule_names,
                "confidence": 1.0,
                "evidence": None,
            }
        )
    return out


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

        web_acl_summaries = meta.get("web_acls") or []
        orphan_acl_names: set = set(meta.get("orphan_acl_names") or set())

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
                        "web_acls": web_acl_summaries,
                        "failure_reason": (
                            f"No Web ACLs found in scope "
                            f"region={run.get('region')} account={run['account_id']}"
                        ),
                    }
                },
            )
            return

        suspicious_reqs = meta.get("suspicious_requests")
        if suspicious_reqs:
            result = ai_pipeline.run_pipeline(
                rules, suspicious_requests=suspicious_reqs
            )
        else:
            result = ai_pipeline.run_pipeline(rules)
        enriched_rules: List[Dict[str, Any]] = result.get("rules", [])
        raw_findings: List[Dict[str, Any]] = result.get("findings", [])
        total = len(enriched_rules)

        rule_docs: List[Dict[str, Any]] = []
        web_acls_seen: set = set()
        rules_by_name: Dict[str, Dict[str, Any]] = {}
        rules_by_acl: Dict[str, List[Dict[str, Any]]] = {}
        for r in enriched_rules:
            ai = r.get("ai_explanation") or {}
            rule_kind = r.get("rule_kind") or aws_waf.classify_rule_kind(
                r.get("statement_json") or {}
            )
            doc = {
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
                "rule_kind": rule_kind,
                "ai_explanation": ai.get("explanation"),
                "ai_working": ai.get("working"),
                "ai_concerns": ai.get("concerns"),
            }
            rule_docs.append(doc)
            web_acls_seen.add(r["web_acl_name"])
            rules_by_name[r["rule_name"]] = doc
            rules_by_acl.setdefault(r["web_acl_name"], []).append(doc)
        if rule_docs:
            db["rules"].insert_many(rule_docs)

        # Phase 5 — apply guardrails AFTER LLM, then append orphan-ACL findings.
        guarded = _apply_phase5_finding_guardrails(
            raw_findings, rules_by_name, orphan_acl_names
        )
        # Phase 5.2 — replace naive name-based duplicates with resource-aware logic.
        guarded = _resource_aware_duplicate_findings(
            guarded, rules_by_name, rules_by_acl, web_acl_summaries
        )
        orphan_findings = _orphaned_acl_findings(web_acl_summaries, rules_by_acl)
        final_findings = guarded + orphan_findings

        finding_docs: List[Dict[str, Any]] = []
        for f in final_findings:
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
                    "evidence": f.get("evidence"),
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
                    "web_acl_count": meta.get("web_acl_count", len(web_acls_seen)),
                    "rule_count": len(rule_docs),
                    "estimated_waste_usd": waste,
                    "estimated_waste_breakdown": breakdown,
                    "fms_visibility": meta.get("fms_visibility"),
                    "logging_available": meta.get("logging_available"),
                    "data_source": meta.get("data_source"),
                    "web_acls": web_acl_summaries,
                    # Phase 5.5 — audit-time evidence sample (top-50 ALLOW
                    # requests that scored above SUSPICION_THRESHOLD). Drives
                    # the PDF "Observed WAF Gaps" section and survives for
                    # post-hoc review of every bypass_candidate finding.
                    "suspicious_request_sample": meta.get(
                        "suspicious_requests"
                    ) or [],
                    # Phase 5 production debug — first 5 raw log events
                    # actually fetched by the bypass sampler. Lets an
                    # operator diagnose log-shape surprises when production
                    # results don't match expectations.
                    "debug_log_sample": meta.get("debug_log_sample") or [],
                    "scopes": meta.get("scopes") or [],
                }
            },
        )
        db["accounts"].update_one(
            {"account_id": run["account_id"]},
            {"$set": {"last_audit_at": _utcnow()}},
        )
        logger.info(
            "Audit %s complete | source=%s rules=%d findings=%d waste=$%.2f "
            "orphaned_acls=%d",
            audit_run_id,
            meta.get("data_source"),
            len(rule_docs),
            len(finding_docs),
            waste,
            len(orphan_acl_names),
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
