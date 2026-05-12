"""Phase 5.3.2 — bug fixes + Impact field + Methodology PDF appendix."""
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

import mongomock
import pytest

from services import audit as audit_mod
from services import db as db_mod
from services import ai_pipeline
from services import remediation as remediation_mod


# --- Fix 1 — bypass affected_rules invariant ------------------------------


def test_detect_bypasses_raises_without_acl_tag_or_fallback(monkeypatch):
    """The function MUST refuse to emit a bypass with empty
    affected_rules — invariant baked in via assertion."""
    monkeypatch.setattr(ai_pipeline, "_chat_json", lambda *_a, **_kw: {
        "gaps": [{"pattern_type": "shellshock", "severity": "high",
                  "confidence": 0.95, "example_uri": "/x"}]
    })
    with pytest.raises(AssertionError):
        ai_pipeline.detect_bypasses(
            [{"httpRequest": {"uri": "/x", "args": "", "headers": []}}],
        )


def test_detect_bypasses_uses_acl_tag_when_present(monkeypatch):
    """When suspicious requests carry `_web_acl_name`, the bypass
    finding's `affected_rules` lists every distinct ACL observed."""
    monkeypatch.setattr(ai_pipeline, "_chat_json", lambda *_a, **_kw: {
        "gaps": [{"pattern_type": "shellshock", "severity": "high",
                  "confidence": 0.95, "example_uri": "/x"}]
    })
    findings = ai_pipeline.detect_bypasses([
        {"httpRequest": {"uri": "/a"}, "_web_acl_name": "acl-cf"},
        {"httpRequest": {"uri": "/b"}, "_web_acl_name": "acl-r"},
        {"httpRequest": {"uri": "/c"}, "_web_acl_name": "acl-cf"},
    ])
    assert len(findings) == 1
    assert set(findings[0]["affected_rules"]) == {"acl-cf", "acl-r"}


def test_detect_bypasses_falls_back_to_supplied_acl_names(monkeypatch):
    monkeypatch.setattr(ai_pipeline, "_chat_json", lambda *_a, **_kw: {
        "gaps": [{"pattern_type": "shellshock", "severity": "high",
                  "confidence": 0.95, "example_uri": "/x"}]
    })
    findings = ai_pipeline.detect_bypasses(
        [{"httpRequest": {"uri": "/x"}}],
        web_acl_names_fallback=["acl-fallback"],
    )
    assert findings[0]["affected_rules"] == ["acl-fallback"]


# --- Fix 2 — quick_win remediation dispatch -------------------------------


def test_quick_win_unused_uses_obsolete_copy():
    """Single-rule quick_win (no shared_resource, no stranded evidence)
    must use the 'obsolete / delete' template, NOT the duplicate-pair
    template."""
    finding = {
        "type": "quick_win",
        "affected_rules": ["BlockOldCurlScanners"],
        # No evidence — i.e. the AI emitted a plain quick_win.
    }
    rem = remediation_mod.remediation_for(finding)
    actions_text = " ".join(rem["suggested_actions"]).lower()
    assert "obsolete" in actions_text or "delete the rule" in actions_text
    assert "redundant pair" not in actions_text
    assert "weaker" not in actions_text


def test_quick_win_shared_resource_keeps_redundancy_copy():
    """Phase 5.3.2 — `quick_win` from the resource-aware dedup pass
    (evidence='shared_resource') keeps the redundancy-pair template."""
    finding = {
        "type": "quick_win",
        "evidence": "shared_resource",
        "affected_rules": ["BlockAdminPath__a", "BlockAdminPath__b"],
    }
    rem = remediation_mod.remediation_for(finding)
    actions_text = " ".join(rem["suggested_actions"]).lower()
    assert "redundancy" in actions_text or "weaker" in actions_text


# --- Fix 3 — dead_rule severity rubric ------------------------------------


def _run_dead_rule_severity_audit(monkeypatch, *, also_emit_bypass: bool):
    """Helper — run a complete audit with one dead_rule (HIGH from the AI)
    and optionally a co-existing bypass_candidate. Returns the persisted
    dead_rule finding."""
    db = mongomock.MongoClient()[
        "ruleiq_fix1_bypass" if also_emit_bypass else "ruleiq_fix1_nobypass"
    ]
    db_mod.set_test_db(db)

    rule = {
        "rule_name": "LegacyDeadRule", "web_acl_name": "acl-x",
        "priority": 5, "action": "BLOCK", "rule_kind": "custom",
        "statement_json": {}, "hit_count": 0, "count_mode_hits": 0,
        "last_fired": None, "sample_uris": [],
        "fms_managed": False, "override_action": None,
        "managed_rule_overrides": [],
    }

    def fake_load(*_a, **_kw):
        return [rule], {
            "data_source": "fixture", "fms_visibility": None,
            "logging_available": True, "web_acl_count": 1,
            "web_acls": [{"name": "acl-x", "scope": "REGIONAL", "arn": None,
                          "attached_resources": ["demo://x"], "attached": True}],
            "orphan_acl_names": set(),
            "suspicious_requests": [],
        }
    monkeypatch.setattr(audit_mod, "_load_rules_from_fixtures", fake_load)
    monkeypatch.setenv("DEMO_MODE", "true")

    findings = [{
        "type": "dead_rule", "severity": "high",
        "title": "LegacyDeadRule Not Firing",
        "description": "x", "recommendation": "y",
        "affected_rules": ["LegacyDeadRule"], "confidence": 0.7,
    }]
    if also_emit_bypass:
        findings.append({
            "type": "bypass_candidate", "severity": "high",
            "title": "Possible WAF bypass: shellshock",
            "description": "x", "recommendation": "y",
            "affected_rules": ["acl-x"], "confidence": 0.9,
            "evidence": "log-sample",
        })

    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline",
        lambda rules, **_kw: {
            "rules": [{**r, "ai_explanation": {"explanation": "m",
                       "working": True, "concerns": None}} for r in rules],
            "findings": findings,
        })

    audit_id = audit_mod.create_audit_run(
        db=db, account_id="123456789012", role_arn=None,
        region="us-east-1", log_window_days=30, external_id=None,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    return next(
        f for f in db["findings"].find({"audit_run_id": audit_id})
        if f["type"] == "dead_rule"
    )


def test_dead_rule_severity_always_medium_without_bypass(monkeypatch):
    """Fix #1 — dead_rule is MEDIUM when no bypass_candidate exists."""
    dead = _run_dead_rule_severity_audit(monkeypatch, also_emit_bypass=False)
    assert dead["severity"] == "medium"


def test_dead_rule_severity_always_medium_with_bypass(monkeypatch):
    """Fix #1 — dead_rule is MEDIUM even when a bypass_candidate co-exists.

    The earlier heuristic (Phase 5.3.2) preserved HIGH on dead_rule
    whenever ANY bypass fired in the same audit, regardless of whether
    the dead rule's intent matched the bypass signature class. That
    correlation was too coarse; we now always downgrade.

    Smart signature-class correlation is tracked in GitHub issue #4 (P2)
    and is intentionally NOT implemented here.
    """
    dead = _run_dead_rule_severity_audit(monkeypatch, also_emit_bypass=True)
    assert dead["severity"] == "medium"


# --- Fix 4 — conflict regression ------------------------------------------


def test_conflict_finding_preserved_when_acls_protect_different_resources():
    """Phase 5.3.2 — a `conflict` finding for the same rule name on two
    distinct attached ACLs (different resources) must NOT be suppressed."""
    finding = {
        "type": "conflict", "severity": "medium",
        "affected_rules": ["BlockAdminPath__a", "BlockAdminPath__b"],
        "title": "Duplicated Rules Detected",
        "description": "x", "recommendation": "y", "confidence": 0.7,
    }
    rbm = {
        "BlockAdminPath__a": {
            "rule_name": "BlockAdminPath", "web_acl_name": "acl-a",
            "rule_kind": "custom",
        },
        "BlockAdminPath__b": {
            "rule_name": "BlockAdminPath", "web_acl_name": "acl-b",
            "rule_kind": "custom",
        },
    }
    rba = {
        "acl-a": [rbm["BlockAdminPath__a"]],
        "acl-b": [rbm["BlockAdminPath__b"]],
    }
    summaries = [
        {"name": "acl-a", "scope": "REGIONAL", "attached": True,
         "attached_resources": [{"arn": "arn:alb:a", "type": "ALB",
                                  "id": "alb-a", "friendly": "alb-a"}]},
        {"name": "acl-b", "scope": "REGIONAL", "attached": True,
         "attached_resources": [{"arn": "arn:alb:b", "type": "ALB",
                                  "id": "alb-b", "friendly": "alb-b"}]},
    ]
    out = audit_mod._resource_aware_duplicate_findings(
        [finding], rbm, rba, summaries,
    )
    assert len(out) == 1, f"expected conflict preserved, got {out}"
    assert out[0]["type"] == "conflict"
    assert out[0]["evidence"] == "cross_acl_same_name"


# --- Fix 6 — Impact field --------------------------------------------------


def test_impact_field_present_on_every_persisted_finding(monkeypatch):
    """Every persisted finding has a non-empty `impact` string."""
    db = mongomock.MongoClient()["ruleiq_phase5_3_2_impact"]
    db_mod.set_test_db(db)

    def fake_load(*_a, **_kw):
        return [{
            "rule_name": "R1", "web_acl_name": "acl-x",
            "priority": 0, "action": "COUNT", "rule_kind": "custom",
            "statement_json": {}, "hit_count": 5000, "count_mode_hits": 5000,
            "last_fired": None, "sample_uris": [],
            "fms_managed": False, "override_action": None,
            "managed_rule_overrides": [],
        }], {
            "data_source": "fixture", "fms_visibility": None,
            "logging_available": True, "web_acl_count": 1,
            "web_acls": [{"name": "acl-x", "scope": "REGIONAL", "arn": None,
                          "attached_resources": ["demo://x"], "attached": True}],
            "orphan_acl_names": set(),
            "suspicious_requests": [],
        }
    monkeypatch.setattr(audit_mod, "_load_rules_from_fixtures", fake_load)
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline",
        lambda rules, **_kw: {
            "rules": [{**r, "ai_explanation": {"explanation": "m",
                       "working": True, "concerns": None}} for r in rules],
            "findings": [
                {"type": "bypass_candidate", "severity": "high",
                 "title": "x", "description": "y", "recommendation": "z",
                 "affected_rules": ["acl-x"], "confidence": 0.95,
                 "evidence": "log-sample"},
                {"type": "fms_review", "severity": "low",
                 "title": "x", "description": "y", "recommendation": "z",
                 "affected_rules": [], "confidence": 0.7},
            ],
        })

    audit_id = audit_mod.create_audit_run(
        db=db, account_id="123456789012", role_arn=None,
        region="us-east-1", log_window_days=30, external_id=None,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    findings = list(db["findings"].find({"audit_run_id": audit_id}))
    for f in findings:
        assert isinstance(f.get("impact"), str) and f["impact"], (
            f"finding {f['type']} has empty impact"
        )
    # COUNT-mode rule produces a count_mode_with_hits + count_mode_high_volume.
    count_with = next(
        f for f in findings if f["type"] == "count_mode_with_hits"
    )
    assert "logging instead of blocking" in count_with["impact"]


def test_impact_copy_for_quick_win_unused_is_distinct_from_stranded():
    """Phase 5.3.2 — `quick_win` (unused single rule) uses the
    quick_win_unused impact; stranded uses stranded_rule impact."""
    unused = remediation_mod.impact_for({"type": "quick_win", "affected_rules": ["X"]})
    stranded = remediation_mod.impact_for(
        {"type": "quick_win", "evidence": "stranded", "affected_rules": ["X"]}
    )
    assert unused
    assert stranded
    assert unused != stranded
    assert "Low-risk rule cleanup" in unused
    assert "orphaned Web ACL" in stranded


# --- Fix 7 — PDF Impact + Methodology appendix ----------------------------


def test_pdf_contains_impact_per_finding_and_methodology_appendix():
    from pypdf import PdfReader
    from services.pdf_report import render_audit_pdf
    import datetime as _dt

    run = {
        "_id": "x", "account_id": "123456789012", "data_source": "aws",
        "rule_count": 0, "web_acl_count": 0,
        "estimated_waste_usd": 0.0, "estimated_waste_breakdown": [],
        "created_at": _dt.datetime.now(_dt.timezone.utc),
        "completed_at": _dt.datetime.now(_dt.timezone.utc),
        "scopes": ["REGIONAL"], "web_acls": [],
    }
    findings = [
        {"type": "bypass_candidate", "severity": "high",
         "title": "Bypass", "description": "y", "recommendation": "z",
         "affected_rules": ["acl-x"], "confidence": 0.95,
         "severity_score": 90, "impact": "ATTACK IMPACT TEXT.",
         "suggested_actions": ["A1."], "verify_by": "V1.",
         "disclaimer": "EdgePosture does not generate WAF rules."},
        {"type": "dead_rule", "severity": "medium",
         "title": "Dead", "description": "y", "recommendation": "z",
         "affected_rules": ["R1"], "confidence": 0.7,
         "severity_score": 50, "impact": "DEAD IMPACT TEXT.",
         "suggested_actions": ["A1."], "verify_by": "V1.",
         "disclaimer": "EdgePosture does not generate WAF rules."},
    ]
    pdf_bytes = render_audit_pdf(run, [], findings)
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
    # Impact label appears at least once per finding.
    assert text.count("Impact") >= len(findings)
    assert "ATTACK IMPACT TEXT" in text
    assert "DEAD IMPACT TEXT" in text
    # Methodology appendix is present once and contains the score subsection.
    assert "Methodology" in text
    assert "Severity score (0" in text
    assert "Confidence (0–100%)" in text or "Confidence (0" in text
