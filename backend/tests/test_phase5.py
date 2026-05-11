"""Phase 5 — Analysis Quality.

Coverage:
* scoring.kind_severity: managed-zero-hits is LOW, custom-zero-hits is HIGH.
* scoring.estimated_waste_usd: excludes managed + FMS rules from waste.
* aws_waf.classify_rule_kind: managed/rate_based/custom from Statement shape.
* aws_waf.derive_mode: OverrideAction.None → 'Block (group)' for managed
  rules (the misread that was producing 'ALLOW' in Phase 4).
* ai_pipeline._extract_managed_group_name + MANAGED_RULE_CONTEXT: domain
  hint is injected into the Pass-1 user message for known managed groups.
* audit.run_audit_pipeline: orphaned-ACL detection, rule_kind persisted,
  web_acls summary persisted, dead_rule findings on orphan ACLs suppressed,
  one `orphaned_web_acl` finding emitted per orphan ACL, FMS/managed-only
  affected_rules retyped to fms_review at severity=low.
* /api/health returns phase '5'.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import mongomock
import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)
os.environ.setdefault("DEMO_MODE", "true")

from services import ai_pipeline  # noqa: E402
from services import audit as audit_mod  # noqa: E402
from services import aws_waf  # noqa: E402
from services import db as db_mod  # noqa: E402
from services import scoring  # noqa: E402
import main  # noqa: E402


# ---- 1. Severity table ------------------------------------------------------


def test_kind_severity_custom_zero_hits_is_high():
    label, score = scoring.kind_severity("custom", 0)
    assert label == "high"
    assert score >= 80


def test_kind_severity_managed_zero_hits_is_low():
    """Managed defensive rules with zero hits are NORMAL, not waste."""
    label, score = scoring.kind_severity("managed", 0)
    assert label == "low"
    assert score < 40


def test_kind_severity_rate_based_zero_is_medium():
    label, _ = scoring.kind_severity("rate_based", 0)
    assert label == "medium"


def test_kind_severity_healthy_traffic_is_low_for_all_kinds():
    for kind in ("custom", "managed", "rate_based"):
        label, _ = scoring.kind_severity(kind, 10_000)
        assert label == "low"


# ---- 2. Waste accounting ----------------------------------------------------


def test_estimated_waste_excludes_managed_and_fms_rules():
    rules = [
        {"rule_name": "DeadCustomRule",  "rule_kind": "custom",     "hit_count": 0, "fms_managed": False},
        {"rule_name": "ManagedZeroHit",  "rule_kind": "managed",    "hit_count": 0, "fms_managed": False},
        {"rule_name": "FMSManaged",      "rule_kind": "managed",    "hit_count": 0, "fms_managed": True},
        {"rule_name": "ActiveCustom",    "rule_kind": "custom",     "hit_count": 99, "fms_managed": False},
        {"rule_name": "RateBasedZero",   "rule_kind": "rate_based", "hit_count": 0, "fms_managed": False},
    ]
    # Only DeadCustomRule + RateBasedZero are "truly dead customer" — but the
    # spec is unambiguous about *managed* exclusion. RateBasedZero remains
    # waste because its kind is rate_based (custom-class), not managed.
    waste = scoring.estimated_waste_usd(rules)
    # rule fee is $1/month — expect $2 total (DeadCustomRule + RateBasedZero)
    assert waste == pytest.approx(2.0)
    breakdown = scoring.estimated_waste_breakdown(rules)
    names = {b["rule_name"] for b in breakdown}
    assert "DeadCustomRule" in names
    assert "ManagedZeroHit" not in names
    assert "FMSManaged" not in names


# ---- 3. Rule kind classification --------------------------------------------


def test_classify_rule_kind_managed():
    stmt = {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "X"}}
    assert aws_waf.classify_rule_kind(stmt) == "managed"


def test_classify_rule_kind_rate_based():
    stmt = {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}}
    assert aws_waf.classify_rule_kind(stmt) == "rate_based"


def test_classify_rule_kind_nested_inside_and():
    stmt = {
        "AndStatement": {
            "Statements": [
                {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "Y"}},
                {"ByteMatchStatement": {}},
            ]
        }
    }
    assert aws_waf.classify_rule_kind(stmt) == "managed"


def test_classify_rule_kind_custom_default():
    stmt = {"ByteMatchStatement": {"FieldToMatch": {"UriPath": {}}}}
    assert aws_waf.classify_rule_kind(stmt) == "custom"


# ---- 4. derive_mode (OverrideAction misread fix) ---------------------------


def test_derive_mode_managed_override_none_is_block_group():
    """The Phase 4 bug: OverrideAction.None was rendered as 'ALLOW'."""
    rule = {"OverrideAction": {"None": {}}}
    assert aws_waf.derive_mode(rule, "managed") == "Block (group)"


def test_derive_mode_managed_override_count_is_count_override():
    rule = {"OverrideAction": {"Count": {}}}
    assert aws_waf.derive_mode(rule, "managed") == "Count (override)"


def test_derive_mode_managed_missing_override_defaults_to_group():
    assert aws_waf.derive_mode({}, "managed") == "Block (group)"


def test_derive_mode_custom_action_block():
    rule = {"Action": {"Block": {}}}
    assert aws_waf.derive_mode(rule, "custom") == "BLOCK"


# ---- 5. MANAGED_RULE_CONTEXT injection in Pass 1 ---------------------------


def test_extract_managed_group_name_from_statement():
    rule = {
        "rule_name": "X",
        "statement_json": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesCommonRuleSet",
            }
        },
    }
    assert ai_pipeline._extract_managed_group_name(rule) == "AWSManagedRulesCommonRuleSet"


def test_extract_managed_group_name_from_fms_prefixed_name():
    rule = {
        "rule_name": "FMS-AWSManagedRulesAmazonIpReputationList",
        "statement_json": {},
    }
    name = ai_pipeline._extract_managed_group_name(rule)
    assert name == "AWSManagedRulesAmazonIpReputationList"


def test_extract_managed_group_name_unknown_returns_none():
    rule = {"rule_name": "CustomerCustomRule_42", "statement_json": {}}
    assert ai_pipeline._extract_managed_group_name(rule) is None


def test_explain_rule_injects_managed_context(monkeypatch):
    """Pass-1 user message MUST contain the domain hint when the rule is a
    known AWS managed group."""
    captured: Dict[str, str] = {}

    def fake_chat(system: str, user: str) -> Dict[str, Any]:
        captured["user"] = user
        return {"explanation": "ok", "working": True, "concerns": None}

    monkeypatch.setattr(ai_pipeline, "_chat_json", fake_chat)
    rule = {
        "rule_name": "FMS-AWSManagedRulesAmazonIpReputationList",
        "statement_json": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesAmazonIpReputationList",
            }
        },
        "hit_count": 0,
        "fms_managed": True,
    }
    ai_pipeline.explain_rule(rule)
    assert "AWSManagedRulesAmazonIpReputationList" in captured["user"]
    assert "DOMAIN CONTEXT" in captured["user"]
    # The full reputation-list guidance text must appear.
    assert "threat intel" in captured["user"].lower()


# ---- 6. Health phase --------------------------------------------------------


@pytest.fixture()
def db():
    mock = mongomock.MongoClient()["ruleiq_phase5"]
    db_mod.set_test_db(mock)
    yield mock
    db_mod.clear_test_db()


@pytest.fixture()
def client(db) -> TestClient:
    return TestClient(main.app)


def test_health_reports_phase_5(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["phase"] == "5"


# ---- 7. End-to-end audit pipeline w/ mocked LLM ----------------------------


def _mocked_pipeline(rules: List[Dict[str, Any]], suspicious_requests=None):
    """Stand-in for ai_pipeline.run_pipeline. Mirrors real shape & runs the
    same guardrails downstream of audit.py would apply to real LLM output.
    Emits at least one finding of every type so the guardrail behaviour can
    be observed.
    """
    enriched = [{**r, "ai_explanation": {"explanation": "mock", "working": True, "concerns": None}} for r in rules]
    findings: List[Dict[str, Any]] = []
    for r in rules:
        if r.get("fms_managed") and (r.get("hit_count") or 0) == 0:
            findings.append({
                "type": "fms_review", "severity": "low",
                "affected_rules": [r["rule_name"]],
                "title": "FMS rule with zero hits",
                "description": "Centrally managed",
                "recommendation": "Flag for review",
                "confidence": 0.9,
            })
        elif (r.get("hit_count") or 0) == 0 and not r.get("fms_managed"):
            # IMPORTANT: emit a dead_rule even for managed rules to test that
            # audit.py's guardrail re-types them.
            findings.append({
                "type": "dead_rule", "severity": "medium",
                "affected_rules": [r["rule_name"]],
                "title": f"Dead: {r['rule_name']}",
                "description": "Zero hits in 30d",
                "recommendation": "Remove",
                "confidence": 0.8,
            })
    # Synthetic conflict + quick_win + bypass for coverage
    findings.append({
        "type": "conflict", "severity": "medium",
        "affected_rules": [r["rule_name"] for r in rules[:2]],
        "title": "Overlap", "description": "two rules touch",
        "recommendation": "Reorder", "confidence": 0.7,
    })
    findings.append({
        "type": "quick_win", "severity": "low",
        "affected_rules": [rules[0]["rule_name"]],
        "title": "Easy", "description": "redundant", "recommendation": "delete",
        "confidence": 0.6,
    })
    findings.append({
        "type": "bypass_candidate", "severity": "high",
        "affected_rules": [rules[0]["rule_name"]],
        "title": "Possible bypass", "description": "weird traffic shape",
        "recommendation": "Investigate", "confidence": 0.75,
    })
    return {"rules": enriched, "findings": findings}


def test_audit_pipeline_persists_rule_kind_on_every_rule(client, db, monkeypatch):
    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline", _mocked_pipeline)
    resp = client.post(
        "/api/audits",
        json={"account_id": "111122223333", "region": "us-east-1"},
    )
    assert resp.status_code == 202
    audit_id = resp.json()["audit_run_id"]
    audit_mod.run_audit_pipeline(audit_id, db)

    rules = list(db["rules"].find({"audit_run_id": audit_id}))
    assert rules, "rules should be persisted"
    for r in rules:
        assert "rule_kind" in r
        assert r["rule_kind"] in {"custom", "managed", "rate_based"}
    # The two FMS-prefixed managed rule groups in the fixture must classify
    # as 'managed', not 'custom'.
    managed = [r for r in rules if r["rule_kind"] == "managed"]
    assert any(r["fms_managed"] for r in managed), "managed rules expected"


def test_audit_pipeline_persists_web_acls_summary(client, db, monkeypatch):
    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline", _mocked_pipeline)
    resp = client.post(
        "/api/audits",
        json={"account_id": "111122223333", "region": "us-east-1"},
    )
    audit_id = resp.json()["audit_run_id"]
    audit_mod.run_audit_pipeline(audit_id, db)
    run = db["audit_runs"].find_one({"_id": audit_id})
    assert run["web_acls"] is not None
    assert len(run["web_acls"]) >= 1
    for acl in run["web_acls"]:
        assert "name" in acl and "attached" in acl


def test_audit_guardrails_retype_managed_dead_to_fms_review(client, db, monkeypatch):
    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline", _mocked_pipeline)
    resp = client.post(
        "/api/audits",
        json={"account_id": "111122223333", "region": "us-east-1"},
    )
    audit_id = resp.json()["audit_run_id"]
    audit_mod.run_audit_pipeline(audit_id, db)
    findings = list(db["findings"].find({"audit_run_id": audit_id}))
    # No dead_rule / quick_win finding should reference a managed rule.
    managed_names = {
        r["rule_name"]
        for r in db["rules"].find({"audit_run_id": audit_id, "rule_kind": "managed"})
    }
    for f in findings:
        if f["type"] in {"dead_rule", "quick_win"}:
            assert not (set(f["affected_rules"]) & managed_names), (
                f"Managed rule leaked into removal finding: {f}"
            )
    # All fms_review findings are severity=low.
    for f in findings:
        if f["type"] == "fms_review":
            assert f["severity"] == "low"


# ---- 8. Orphaned-ACL detection (synthetic AWS path) -------------------------


def test_orphan_acl_findings_emitted_and_dead_rules_suppressed(db, monkeypatch):
    """End-to-end orphan-ACL behaviour using a synthetic _load_rules_from_aws
    that returns one attached ACL and one orphaned ACL."""
    audit_id = audit_mod.create_audit_run(
        db=db,
        account_id="111122223333",
        role_arn="arn:aws:iam::111122223333:role/X",
        region="us-east-1",
        log_window_days=30,
        external_id="x" * 32,
    )

    def fake_loader(**_kw):
        rules = [
            {
                "rule_name": "DeadRuleInAttachedACL",
                "web_acl_name": "acl-attached",
                "priority": 10,
                "action": "BLOCK",
                "rule_kind": "custom",
                "statement_json": {"ByteMatchStatement": {}},
                "hit_count": 0,
                "last_fired": None,
                "count_mode_hits": 0,
                "sample_uris": [],
                "fms_managed": False,
                "override_action": None,
            },
            {
                "rule_name": "DeadRuleInOrphanACL",
                "web_acl_name": "acl-orphan",
                "priority": 20,
                "action": "BLOCK",
                "rule_kind": "custom",
                "statement_json": {"ByteMatchStatement": {}},
                "hit_count": 0,
                "last_fired": None,
                "count_mode_hits": 0,
                "sample_uris": [],
                "fms_managed": False,
                "override_action": None,
            },
        ]
        meta = {
            "data_source": "aws",
            "fms_visibility": True,
            "logging_available": True,
            "web_acl_count": 2,
            "web_acls": [
                {
                    "name": "acl-attached",
                    "scope": "REGIONAL",
                    "arn": "arn:aws:wafv2:us-east-1:1:regional/webacl/acl-attached/abc",
                    "attached_resources": [
                        "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/foo/123"
                    ],
                    "attached": True,
                },
                {
                    "name": "acl-orphan",
                    "scope": "REGIONAL",
                    "arn": "arn:aws:wafv2:us-east-1:1:regional/webacl/acl-orphan/def",
                    "attached_resources": [],
                    "attached": False,
                },
            ],
            "orphan_acl_names": {"acl-orphan"},
            "suspicious_requests": [],
        }
        return rules, meta

    # Patch the loader + the pipeline + force AWS path (role_arn present).
    monkeypatch.setattr(audit_mod, "_load_rules_from_aws", fake_loader)
    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline", _mocked_pipeline)
    monkeypatch.setenv("DEMO_MODE", "false")
    audit_mod.run_audit_pipeline(audit_id, db)

    findings = list(db["findings"].find({"audit_run_id": audit_id}))
    types = [f["type"] for f in findings]

    # 1) at least one orphaned_web_acl finding exists for acl-orphan
    orphan_findings = [f for f in findings if f["type"] == "orphaned_web_acl"]
    assert orphan_findings, "expected orphaned_web_acl finding"
    assert any("acl-orphan" in (f["title"] or "") for f in orphan_findings)

    # 2) NO dead_rule finding on DeadRuleInOrphanACL (suppressed)
    for f in findings:
        if f["type"] == "dead_rule":
            assert "DeadRuleInOrphanACL" not in f["affected_rules"]

    # 3) dead_rule on attached ACL survived
    assert any(
        f["type"] == "dead_rule" and "DeadRuleInAttachedACL" in f["affected_rules"]
        for f in findings
    ), f"dead_rule on attached ACL missing; types={types}"

    # 4) the audit_run persisted the web_acls summary
    run = db["audit_runs"].find_one({"_id": audit_id})
    names = {a["name"] for a in run["web_acls"]}
    assert names == {"acl-attached", "acl-orphan"}


# ---- 9. /api/audits/{id} surfaces web_acls in serialized run ---------------


def test_get_audit_returns_web_acls_field(client, db, monkeypatch):
    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline", _mocked_pipeline)
    resp = client.post(
        "/api/audits",
        json={"account_id": "111122223333", "region": "us-east-1"},
    )
    audit_id = resp.json()["audit_run_id"]
    audit_mod.run_audit_pipeline(audit_id, db)
    body = client.get(f"/api/audits/{audit_id}").json()
    assert "web_acls" in body
    assert isinstance(body["web_acls"], list)
    assert all("attached" in a and "name" in a for a in body["web_acls"])
