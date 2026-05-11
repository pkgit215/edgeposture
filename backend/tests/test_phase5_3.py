"""Phase 5.3 tests — remediation, COUNT-mode findings, managed overrides."""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)

import pytest

from services import audit as audit_mod
from services import aws_waf
from services import pdf_report
from services import remediation as remediation_mod


# --- Phase 5.3.1 — remediation lookup --------------------------------------


def test_remediation_table_has_disclaimer_for_every_known_type():
    types = [
        "bypass_candidate", "dead_rule", "orphaned_web_acl",
        "stranded_rule", "rule_conflict", "quick_win",
        "count_mode_with_hits", "count_mode_high_volume",
        "count_mode_long_duration", "managed_rule_override_count",
        "fms_review",
    ]
    for t in types:
        finding = {"type": t, "affected_rules": []}
        rem = remediation_mod.remediation_for(finding, {})
        assert rem["disclaimer"] == remediation_mod.UNIVERSAL_DISCLAIMER
        assert rem["suggested_actions"], f"no actions for {t}"
        assert rem["verify_by"], f"no verify_by for {t}"


def test_remediation_dead_rule_managed_vs_custom_dispatch():
    rules = {
        "ManagedA": {"rule_name": "ManagedA", "rule_kind": "managed"},
        "ManagedB": {"rule_name": "ManagedB", "rule_kind": "managed"},
        "CustomA": {"rule_name": "CustomA", "rule_kind": "custom"},
    }
    managed_only = {"type": "dead_rule", "affected_rules": ["ManagedA", "ManagedB"]}
    mixed = {"type": "dead_rule", "affected_rules": ["ManagedA", "CustomA"]}
    rm_m = remediation_mod.remediation_for(managed_only, rules)
    rm_x = remediation_mod.remediation_for(mixed, rules)
    # Managed-only path uses the curl WAF-on-path verifier
    assert "curl" in rm_m["verify_by"]
    # Mixed / any-custom path uses the synthetic-traffic verifier
    assert "synthetic" in rm_x["verify_by"]


def test_remediation_stranded_emits_from_quick_win_with_evidence_stranded():
    finding = {
        "type": "quick_win", "evidence": "stranded", "affected_rules": ["X"],
    }
    rem = remediation_mod.remediation_for(finding)
    actions_text = " ".join(rem["suggested_actions"]).lower()
    assert "orphan" in actions_text or "stranded" in actions_text or "delete" in actions_text


def test_universal_disclaimer_mentions_count_mode_and_rollback():
    d = remediation_mod.UNIVERSAL_DISCLAIMER
    assert "COUNT mode" in d
    assert "Rollback" in d or "rollback" in d


# --- Phase 5.3.2 — COUNT-mode findings -------------------------------------


def _rule(name, action, hits, kind="custom", overrides=None):
    return {
        "rule_name": name,
        "web_acl_name": "acl-x",
        "action": action,
        "rule_kind": kind,
        "hit_count": hits,
        "count_mode_hits": hits,
        "managed_rule_overrides": overrides or [],
        "fms_managed": False,
    }


def test_count_mode_with_hits_emits_for_count_action_with_hits():
    rules = [_rule("R1", "COUNT", 50)]
    out = audit_mod._count_mode_findings(rules)
    types = {f["type"] for f in out}
    assert "count_mode_with_hits" in types
    # 50 hits is below high_volume threshold and below long_duration threshold
    assert "count_mode_high_volume" not in types
    assert "count_mode_long_duration" not in types


def test_count_mode_high_volume_emits_above_threshold():
    rules = [_rule("R1", "COUNT", 5000)]
    out = audit_mod._count_mode_findings(rules)
    types = {f["type"] for f in out}
    assert "count_mode_high_volume" in types
    assert "count_mode_with_hits" in types  # baseline still emitted
    high = next(f for f in out if f["type"] == "count_mode_high_volume")
    assert high["severity"] == "high"


def test_count_mode_long_duration_emits_at_mid_volume():
    rules = [_rule("R1", "COUNT", 250)]
    out = audit_mod._count_mode_findings(rules)
    types = {f["type"] for f in out}
    assert "count_mode_long_duration" in types
    assert "count_mode_high_volume" not in types


def test_count_mode_zero_hits_emits_nothing():
    rules = [_rule("R1", "COUNT", 0)]
    out = audit_mod._count_mode_findings(rules)
    assert out == []


def test_count_mode_block_action_emits_nothing():
    rules = [_rule("R1", "BLOCK", 5000)]
    out = audit_mod._count_mode_findings(rules)
    assert out == []


def test_count_mode_managed_override_count_counts_as_count_mode():
    """`Count (override)` action on a managed group is COUNT mode for our
    purposes — promote-to-block guidance still applies."""
    rules = [_rule("MG1", "Count (override)", 500, kind="managed")]
    out = audit_mod._count_mode_findings(rules)
    assert any(f["type"] == "count_mode_with_hits" for f in out)


# --- Phase 5.3.3 — RuleActionOverrides parsing -----------------------------


def test_rule_action_overrides_extracted_from_managed_group():
    """Synthesise a minimal real-shape ManagedRuleGroupStatement with
    RuleActionOverrides and check the projected rule carries them."""

    class _Client:
        def get_web_acl(self, **kw):
            return {
                "WebACL": {
                    "Name": "acl-x", "Id": "x", "ARN": "arn:acl",
                    "DefaultAction": {"Allow": {}}, "Scope": "REGIONAL",
                    "Rules": [{
                        "Name": "AWS-Common",
                        "Priority": 0,
                        "Statement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "AWSManagedRulesCommonRuleSet",
                                "RuleActionOverrides": [
                                    {"Name": "SizeRestrictions_BODY",
                                     "ActionToUse": {"Count": {}}},
                                    {"Name": "GenericRFI_QUERYARGUMENTS",
                                     "ActionToUse": {"Count": {}}},
                                ],
                            }
                        },
                        "OverrideAction": {"None": {}},
                    }],
                }
            }

    class _Sess:
        def client(self, service, region_name=None):
            return _Client()

    rules = aws_waf.get_web_acl_rules(
        _Sess(),
        {"Name": "acl-x", "Id": "x", "Scope": "REGIONAL", "ARN": "arn:acl"},
    )
    assert len(rules) == 1
    overrides = rules[0]["managed_rule_overrides"]
    assert len(overrides) == 2
    names = {o["name"] for o in overrides}
    assert names == {"SizeRestrictions_BODY", "GenericRFI_QUERYARGUMENTS"}
    assert all(o["action"] == "Count" for o in overrides)


def test_managed_override_findings_emit_one_per_count_override():
    rules = [_rule(
        "AWS-Common", "Block (group)", 0, kind="managed",
        overrides=[
            {"name": "SizeRestrictions_BODY", "action": "Count"},
            {"name": "GenericRFI_QUERYARGUMENTS", "action": "Count"},
        ],
    )]
    out = audit_mod._managed_override_findings(rules)
    assert len(out) == 2
    titles = " ".join(f["title"] for f in out)
    assert "SizeRestrictions_BODY" in titles
    assert "GenericRFI_QUERYARGUMENTS" in titles
    assert all(f["type"] == "managed_rule_override_count" for f in out)


# --- Phase 5.3.1 PDF render — Remediation block ----------------------------


def _minimal_audit_run(findings_extra=None, scopes=None):
    import datetime as _dt
    return {
        "_id": "x", "account_id": "371126261144",
        "data_source": "aws", "rule_count": 0, "web_acl_count": 0,
        "estimated_waste_usd": 0.0, "estimated_waste_breakdown": [],
        "created_at": _dt.datetime.now(_dt.timezone.utc),
        "completed_at": _dt.datetime.now(_dt.timezone.utc),
        "scopes": scopes or ["REGIONAL"],
        "web_acls": [],
    }


def test_pdf_renders_remediation_block_and_disclaimer():
    from pypdf import PdfReader
    run = _minimal_audit_run()
    rem = remediation_mod.remediation_for(
        {"type": "bypass_candidate", "affected_rules": []}
    )
    findings = [{
        "type": "bypass_candidate",
        "severity": "high",
        "title": "Possible WAF bypass",
        "description": "shellshock reached origin",
        "recommendation": "enable KnownBadInputs",
        "affected_rules": [],
        "confidence": 0.9,
        "severity_score": 80,
        "evidence": "log-sample",
        # Phase 5.3.1 — flat keys.
        "suggested_actions": rem["suggested_actions"],
        "verify_by": rem["verify_by"],
        "disclaimer": rem["disclaimer"],
    }]
    pdf_bytes = pdf_report.render_audit_pdf(run, [], findings)
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
    assert "Remediation" in text
    assert "Suggested actions" in text
    assert "Verify by" in text
    assert "RuleIQ does not generate WAF rules" in text


def test_pdf_cover_leads_with_security_posture_not_cost():
    """Phase 5.3.4 — cover page emphasises Security posture over Cost."""
    from pypdf import PdfReader
    run = _minimal_audit_run()
    run["estimated_waste_usd"] = 72.0
    rem = remediation_mod.remediation_for(
        {"type": "bypass_candidate", "affected_rules": []}
    )
    findings = [{
        "type": "bypass_candidate", "severity": "high",
        "title": "x", "description": "y", "recommendation": "z",
        "affected_rules": [], "confidence": 0.9, "severity_score": 80,
        "suggested_actions": rem["suggested_actions"],
        "verify_by": rem["verify_by"],
        "disclaimer": rem["disclaimer"],
    }]
    pdf_bytes = pdf_report.render_audit_pdf(run, [], findings)
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
    sec_idx = text.find("Security posture")
    cost_idx = text.find("Cost optimization")
    assert sec_idx > 0
    assert cost_idx > 0
    assert sec_idx < cost_idx, "Security posture must precede Cost optimization on cover"


def test_pdf_inventory_shows_override_count():
    """Phase 5.3.3 — managed rules with overrides show the count in the
    Rule Inventory rule-name column."""
    from pypdf import PdfReader
    run = _minimal_audit_run()
    rules = [{
        "rule_name": "AWS-Common", "web_acl_name": "acl-x",
        "priority": 0, "action": "Block (group)",
        "hit_count": 10, "last_fired": None, "fms_managed": False,
        "rule_kind": "managed",
        "managed_rule_overrides": [
            {"name": "SizeRestrictions_BODY", "action": "Count"},
        ],
    }]
    pdf_bytes = pdf_report.render_audit_pdf(run, rules, [])
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
    assert "1 override" in text


# --- Integration smoke — full pipeline emits the new finding types ---------


def test_count_mode_findings_persist_through_run_audit_pipeline(monkeypatch):
    """End-to-end: a COUNT-mode rule with hits produces a persisted
    `count_mode_with_hits` finding with remediation attached."""
    import mongomock
    from services import db as db_mod

    db = mongomock.MongoClient()["ruleiq_phase5_3"]
    db_mod.set_test_db(db)

    # Fixture path + force a COUNT rule.
    def fake_load(*_a, **_kw):
        rules = [
            {
                "rule_name": "CountTestRule", "web_acl_name": "acl-x",
                "priority": 10, "action": "COUNT",
                "statement_json": {}, "rule_kind": "custom",
                "hit_count": 5000, "count_mode_hits": 5000,
                "last_fired": None, "sample_uris": [],
                "fms_managed": False, "override_action": None,
                "managed_rule_overrides": [],
            }
        ]
        meta = {
            "data_source": "fixture", "fms_visibility": None,
            "logging_available": True, "web_acl_count": 1,
            "web_acls": [{"name": "acl-x", "scope": "REGIONAL", "arn": None,
                          "attached_resources": ["demo://x"], "attached": True}],
            "orphan_acl_names": set(),
            "suspicious_requests": [],
        }
        return rules, meta

    monkeypatch.setattr(audit_mod, "_load_rules_from_fixtures", fake_load)
    monkeypatch.setenv("DEMO_MODE", "true")

    # No-op AI.
    def fake_pipeline(rules, suspicious_requests=None):
        return {
            "rules": [
                {**r, "ai_explanation": {"explanation": "m", "working": True, "concerns": None}}
                for r in rules
            ],
            "findings": [],
        }
    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline", fake_pipeline)

    audit_id = audit_mod.create_audit_run(
        db=db, account_id="371126261144", role_arn=None,
        region="us-east-1", log_window_days=30, external_id=None,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    findings = list(db["findings"].find({"audit_run_id": audit_id}))
    types = [f["type"] for f in findings]
    assert "count_mode_with_hits" in types
    assert "count_mode_high_volume" in types
    # Remediation FLAT keys attached on every persisted finding
    for f in findings:
        assert isinstance(f.get("suggested_actions"), list) and f["suggested_actions"]
        assert isinstance(f.get("verify_by"), str) and f["verify_by"]
        assert f.get("disclaimer") == remediation_mod.UNIVERSAL_DISCLAIMER
