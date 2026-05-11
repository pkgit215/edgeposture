"""Feat #2 — Flavor B smart (account-aware) remediation.

These tests target the pure-function `smart_remediation_for` plus the
audit-pipeline wiring (`remediation_kind` persistence). Unit-test scope —
the FastAPI handlers, PDF renderer, and frontend are covered separately.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)

import pytest

from services import remediation as rem_mod
from services.remediation import smart_remediation_for


# --- Test fixture helpers -------------------------------------------------


def _rule(rule_name, web_acl_name, **overrides):
    base = {
        "rule_name": rule_name,
        "web_acl_name": web_acl_name,
        "priority": 10,
        "action": "BLOCK",
        "rule_kind": "custom",
        "hit_count": 0,
        "last_fired": None,
        "statement_json": {},
        "fms_managed": False,
        "managed_rule_overrides": [],
    }
    base.update(overrides)
    return base


def _sus(uri, args, acl_name, signature_classes):
    return {
        "httpRequest": {"uri": uri, "args": args, "headers": []},
        "action": "ALLOW",
        "_web_acl_name": acl_name,
        "_signature_classes": signature_classes,
        "_suspicion_score": 0.9,
    }


# =========================================================================
# bypass_candidate
# =========================================================================


def test_smart_bypass_missing_group_recommends_add():
    """Shellshock bypass on an ACL that lacks the Unix rule group → the
    smart recommendation must literally say `Add AWSManagedRulesUnixRuleSet
    at priority {n}`."""
    acl = "prod-cf-edge-acl"
    rules_by_acl = {acl: [
        _rule("BlockBadIPs", acl, priority=10, rule_kind="custom"),
        _rule("AWSManagedRulesCommonRuleSet", acl, priority=20,
              rule_kind="managed"),
    ]}
    finding = {"type": "bypass_candidate", "severity": "high",
               "signature_class": "shellshock", "affected_rules": [acl]}
    suspicious = [_sus("/", "cmd=%28%29", acl, ["shellshock"])]

    out = smart_remediation_for(
        finding, rules_by_name={}, rules_by_acl=rules_by_acl,
        web_acls=[{"name": acl, "scope": "CLOUDFRONT"}],
        suspicious_sample=suspicious,
    )
    assert out is not None
    action = out["suggested_actions"][0]
    assert "Add AWSManagedRulesUnixRuleSet at priority" in action
    assert acl in action  # cites the actual ACL by name
    # Console nav path included.
    assert "WAFv2 → Web ACLs → prod-cf-edge-acl" in action
    # `1 attack-shaped request matched` — count comes from suspicious sample.
    assert "1 attack-shaped request" in action
    # Evidence_samples populated from the suspicious sample (max 3 URIs).
    assert out["evidence_samples"] == ["/?cmd=%28%29"]


def test_smart_bypass_existing_count_recommends_promote():
    """Same ACL but the Unix rule group is already attached and in COUNT
    mode → smart recommendation must say `Promote to BLOCK`."""
    acl = "prod-cf-edge-acl"
    rules_by_acl = {acl: [
        _rule("AWSManagedRulesUnixRuleSet", acl, priority=20,
              rule_kind="managed", action="COUNT"),
    ]}
    finding = {"type": "bypass_candidate", "severity": "high",
               "signature_class": "shellshock", "affected_rules": [acl]}
    out = smart_remediation_for(
        finding, rules_by_name={}, rules_by_acl=rules_by_acl, web_acls=[],
        suspicious_sample=[_sus("/", "x", acl, ["shellshock"])],
    )
    assert out is not None
    action = out["suggested_actions"][0]
    assert "Promote to BLOCK" in action
    assert "AWSManagedRulesUnixRuleSet is present on prod-cf-edge-acl" in action


def test_smart_bypass_existing_block_recommends_priority_review():
    """Rule group is already attached AND set to BLOCK — the bypass still
    happened, which means a higher-priority allow rule shadows it. Smart
    advice: review priorities below the group."""
    acl = "prod-cf-edge-acl"
    rules_by_acl = {acl: [
        _rule("AllowOfficeIPs", acl, priority=5, action="ALLOW"),
        _rule("AWSManagedRulesUnixRuleSet", acl, priority=20,
              rule_kind="managed", action="BLOCK"),
    ]}
    finding = {"type": "bypass_candidate", "severity": "high",
               "signature_class": "shellshock", "affected_rules": [acl]}
    out = smart_remediation_for(
        finding, rules_by_name={}, rules_by_acl=rules_by_acl, web_acls=[],
        suspicious_sample=[_sus("/", "x", acl, ["shellshock"])],
    )
    assert out is not None
    action = out["suggested_actions"][0]
    assert "review priorities" in action
    assert "priority 20" in action
    # Cites the ACL.
    assert "prod-cf-edge-acl" in action


# =========================================================================
# count_mode_*
# =========================================================================


def test_smart_count_mode_uses_actual_acl_name_and_hit_count():
    acl = "api-gateway-protect"
    rule = _rule("AWSManagedRulesKnownBadInputsRuleSet", acl,
                 rule_kind="managed", action="COUNT",
                 hit_count=4217, count_mode_hits=4217)
    finding = {"type": "count_mode_high_volume", "severity": "high",
               "affected_rules": [rule["rule_name"]]}
    out = smart_remediation_for(
        finding,
        rules_by_name={rule["rule_name"]: rule},
        rules_by_acl={acl: [rule]}, web_acls=[],
        suspicious_sample=[],
    )
    assert out is not None
    action = out["suggested_actions"][0]
    assert "Promote" in action and "BLOCK" in action
    # ACL name AND the exact hit count appear verbatim.
    assert acl in action
    assert "4,217" in action  # formatted with thousands separator
    # Same code path covers the medium-volume sibling type.
    for ftype in ("count_mode_with_hits", "count_mode_long_duration"):
        f2 = {**finding, "type": ftype}
        out2 = smart_remediation_for(
            f2, rules_by_name={rule["rule_name"]: rule},
            rules_by_acl={acl: [rule]}, web_acls=[], suspicious_sample=[],
        )
        assert out2 is not None and "4,217" in out2["suggested_actions"][0]


# =========================================================================
# dead_rule
# =========================================================================


def test_smart_dead_rule_with_matching_intent_cites_observed_count():
    """Dead rule with sqli-shaped intent + sqli-shaped requests in the
    suspicious sample → smart copy must escalate the message and cite the
    observed count."""
    acl = "prod-cf-edge-acl"
    rule = _rule("BlockSQLi", acl, rule_kind="custom",
                 statement_json={"SqliMatchStatement": {
                     "FieldToMatch": {"QueryString": {}},
                     "TextTransformations": [
                         {"Priority": 0, "Type": "URL_DECODE"},
                     ],
                 }})
    finding = {"type": "dead_rule", "severity": "high",
               "signature_class": "sqli", "affected_rules": [rule["rule_name"]]}
    suspicious = [
        _sus("/products", "id=1%27%20OR%201%3D1--", acl, ["sqli"]),
        _sus("/users", "id=1%27%20UNION", acl, ["sqli"]),
    ]
    out = smart_remediation_for(
        finding, rules_by_name={rule["rule_name"]: rule},
        rules_by_acl={acl: [rule]}, web_acls=[],
        suspicious_sample=suspicious,
    )
    assert out is not None
    action = out["suggested_actions"][0]
    assert "2 sqli-shaped requests reached origin" in action
    assert rule["rule_name"] in action
    assert acl in action
    # Evidence URIs flow through.
    assert len(out["evidence_samples"]) == 2


def test_smart_dead_rule_without_observed_traffic_falls_back():
    """No matching attack-shaped traffic in the sample → smart layer
    declines (returns None) so the canned dead_rule copy wins. We don't
    want to escalate without evidence."""
    acl = "internal-alb-waf"
    rule = _rule("BlockSQLi", acl, statement_json={
        "SqliMatchStatement": {"FieldToMatch": {"QueryString": {}}}})
    finding = {"type": "dead_rule", "affected_rules": [rule["rule_name"]]}
    out = smart_remediation_for(
        finding, rules_by_name={rule["rule_name"]: rule},
        rules_by_acl={acl: [rule]}, web_acls=[], suspicious_sample=[],
    )
    assert out is None


# =========================================================================
# orphaned_web_acl
# =========================================================================


def test_smart_orphan_uses_acl_name_and_rule_count():
    acl = "legacy-edge-acl"
    inert = [_rule(f"r{i}", acl) for i in range(14)]
    web_acls = [{"name": acl, "scope": "REGIONAL", "attached": False}]
    finding = {
        "type": "orphaned_web_acl", "severity": "low",
        "title": f"Web ACL '{acl}' is not attached to any resource",
        "affected_rules": [r["rule_name"] for r in inert],
    }
    out = smart_remediation_for(
        finding,
        rules_by_name={r["rule_name"]: r for r in inert},
        rules_by_acl={acl: inert}, web_acls=web_acls, suspicious_sample=[],
    )
    assert out is not None
    action = out["suggested_actions"][0]
    assert acl in action
    assert "REGIONAL" in action
    assert "14 rules inside" in action
    assert "$5/mo" in action
    assert "Console: WAFv2 → Web ACLs → legacy-edge-acl" in action


# =========================================================================
# fallback
# =========================================================================


def test_smart_remediation_falls_back_to_canned_when_no_match():
    """Finding types with no Flavor B variant (e.g. quick_win, fms_review,
    conflict) must return None — caller keeps canned copy."""
    for ftype in ("quick_win", "fms_review", "conflict",
                   "managed_rule_override_count"):
        out = smart_remediation_for(
            {"type": ftype, "affected_rules": ["something"]},
            rules_by_name={}, rules_by_acl={}, web_acls=[],
            suspicious_sample=[],
        )
        assert out is None, f"{ftype} should fall back, got: {out}"


def test_smart_layer_does_not_mutate_finding_or_canned_table():
    """The smart layer is read-only over its inputs and the canned
    `_TABLE`."""
    snapshot = dict(rem_mod._TABLE)  # type: ignore[attr-defined]
    acl = "prod-cf-edge-acl"
    finding = {"type": "bypass_candidate",
               "signature_class": "sqli", "affected_rules": [acl]}
    out = smart_remediation_for(
        finding, rules_by_name={}, rules_by_acl={acl: []},
        web_acls=[], suspicious_sample=[],
    )
    assert out is not None
    # Caller's finding dict is unchanged — caller decides whether to overwrite.
    assert "suggested_actions" not in finding
    # Canned table is untouched.
    assert rem_mod._TABLE == snapshot  # type: ignore[attr-defined]


# =========================================================================
# Integration — `run_audit_pipeline` persists `remediation_kind` correctly
# =========================================================================


def test_persisted_finding_has_remediation_kind():
    """End-to-end: run the real audit pipeline against the local
    fixtures and assert every persisted finding has `remediation_kind`
    set to either `"smart"` or `"canned"`, AND that at least one finding
    is "smart" (proves the wiring fired)."""
    import mongomock
    from services import audit as audit_mod
    from services import db as db_mod

    db = mongomock.MongoClient()["ruleiq_flavorb_test"]
    db_mod.set_test_db(db)

    # Stub the AI pipeline so it always emits a deterministic finding
    # set that exercises both the smart and canned layers. Don't spend
    # any real OpenAI quota.
    def _fake_pipeline(rules, suspicious_requests=None, web_acl_names=None):
        return {
            "rules": [{**r, "ai_explanation": {
                "explanation": "stub", "working": True, "concerns": None}}
                       for r in rules],
            "findings": [
                # bypass — smart layer should fire (signature_class set,
                # ACL exists in rules_by_acl).
                {"type": "bypass_candidate", "severity": "high",
                 "title": "shellshock reached origin",
                 "description": "demo", "recommendation": "demo",
                 "affected_rules": (web_acl_names or ["x"])[:1],
                 "confidence": 0.95, "signature_class": "shellshock"},
                # quick_win — outside the Flavor B scope → canned wins.
                {"type": "quick_win", "severity": "low",
                 "title": "Duplicate rule",
                 "description": "demo", "recommendation": "demo",
                 "affected_rules": [rules[0]["rule_name"]] if rules else [],
                 "confidence": 0.8},
            ],
        }
    _original_pipeline = audit_mod.ai_pipeline.run_pipeline
    audit_mod.ai_pipeline.run_pipeline = _fake_pipeline
    try:
        audit_id = audit_mod.create_audit_run(
            db, "123456789012", None, "us-east-1", 30,
        )
        audit_mod.run_audit_pipeline(audit_id, db)

        findings = list(db["findings"].find({"audit_run_id": audit_id}))
        assert findings, "pipeline produced no findings"
        kinds = {f.get("remediation_kind") for f in findings}
        assert kinds <= {"smart", "canned"}, f"unexpected kinds: {kinds}"
        assert "smart" in kinds, (
            "smart layer never fired — wiring regression"
        )
        # Every persisted finding carries `evidence_samples` (possibly empty).
        for f in findings:
            assert "evidence_samples" in f
            assert isinstance(f["evidence_samples"], list)
    finally:
        # Restore so subsequent tests in this pytest session see the real
        # AI pipeline back in place.
        audit_mod.ai_pipeline.run_pipeline = _original_pipeline
        db_mod.clear_test_db()
