"""Phase 5.3.1-fix — wire-up tests against the 6 acceptance criteria.

Investigation: production audit at
`/api/audits/6a01ec88231a4c1f216db502/findings` returned every finding with
NO `suggested_actions` / `verify_by` / `disclaimer`. `remediation.py`
exists; the audit pipeline simply wasn't attaching the result.

These tests verify the wire-up + the new acceptance criteria the user
will check against the live App Runner after the next push.
"""
from __future__ import annotations

import os
import re
import sys
import io
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)

import mongomock
import pytest
from fastapi.testclient import TestClient

from services import audit as audit_mod
from services import remediation as remediation_mod
from services import db as db_mod


# --- Fix 5 — health phase --------------------------------------------------


def test_health_phase_is_5_3():
    from main import app
    client = TestClient(app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["phase"] == "5.3.2"


# --- Fix 1 — every finding type has remediation FLAT keys persisted --------


_ALL_FINDING_TYPES = [
    ("bypass_candidate", "high"),
    ("dead_rule", "high"),          # custom rule path
    ("count_mode_with_hits", "medium"),
    ("orphaned_web_acl", "medium"),
    ("conflict", "medium"),
    ("fms_review", "low"),
    ("quick_win", "low"),
    ("managed_rule_override_count", "low"),
]


def _make_finding(ftype, severity, affected=None):
    return {
        "type": ftype, "severity": severity,
        "title": f"{ftype} test", "description": f"{ftype} desc",
        "recommendation": "x", "confidence": 0.7,
        "affected_rules": list(affected or []),
    }


def test_wire_up_attaches_flat_remediation_keys_to_every_finding(monkeypatch):
    """Phase 5.3.1 acceptance #3 — every persisted finding has
    `suggested_actions` (non-empty list), `verify_by` (str),
    `disclaimer` (str)."""
    db = mongomock.MongoClient()["ruleiq_phase5_3_1"]
    db_mod.set_test_db(db)

    findings_to_emit = [
        _make_finding(ft, sev, affected=["R1"]) for ft, sev in _ALL_FINDING_TYPES
    ]
    # Add a dead_rule (managed) variant so dead_rule_managed is exercised too.
    findings_to_emit.append(_make_finding("dead_rule", "low", affected=["MR1"]))
    # Add a stranded — emitted as quick_win + evidence="stranded".
    stranded = _make_finding("quick_win", "medium", affected=["R1"])
    stranded["evidence"] = "stranded"
    findings_to_emit.append(stranded)

    rule_R1 = {
        "rule_name": "R1", "web_acl_name": "acl-x",
        "priority": 1, "action": "COUNT", "rule_kind": "custom",
        "statement_json": {}, "hit_count": 100, "count_mode_hits": 100,
        "last_fired": None, "sample_uris": [],
        "fms_managed": False, "override_action": None,
        "managed_rule_overrides": [],
    }
    rule_MR1 = {**rule_R1, "rule_name": "MR1", "rule_kind": "managed",
                "action": "Block (group)", "hit_count": 0,
                "count_mode_hits": 0}

    def fake_load(*_a, **_kw):
        return [rule_R1, rule_MR1], {
            "data_source": "fixture", "fms_visibility": None,
            "logging_available": True, "web_acl_count": 1,
            "web_acls": [{"name": "acl-x", "scope": "REGIONAL", "arn": None,
                          "attached_resources": ["demo://x"], "attached": True}],
            "orphan_acl_names": set(),
            "suspicious_requests": [],
        }
    monkeypatch.setattr(audit_mod, "_load_rules_from_fixtures", fake_load)
    monkeypatch.setenv("DEMO_MODE", "true")

    def fake_pipeline(rules, suspicious_requests=None, **_kw):
        return {
            "rules": [{**r, "ai_explanation": {"explanation": "m",
                       "working": True, "concerns": None}} for r in rules],
            "findings": findings_to_emit,
        }
    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline", fake_pipeline)

    audit_id = audit_mod.create_audit_run(
        db=db, account_id="123456789012", role_arn=None,
        region="us-east-1", log_window_days=30, external_id=None,
    )
    audit_mod.run_audit_pipeline(audit_id, db)

    findings = list(db["findings"].find({"audit_run_id": audit_id}))
    assert findings, "no findings persisted"
    for f in findings:
        actions = f.get("suggested_actions")
        assert isinstance(actions, list) and len(actions) >= 1, (
            f"finding {f['type']} has no suggested_actions: {f!r}"
        )
        assert all(isinstance(a, str) and a for a in actions)
        assert isinstance(f.get("verify_by"), str) and f["verify_by"], (
            f"finding {f['type']} has empty verify_by"
        )
        assert isinstance(f.get("disclaimer"), str) and f["disclaimer"]
        assert f["disclaimer"] == remediation_mod.UNIVERSAL_DISCLAIMER


# --- Fix 3 — bypass affected_rules backfill -------------------------------


def test_bypass_affected_rules_backfilled_with_web_acl_names(monkeypatch):
    """Phase 5.3.1 acceptance #4 — bypass_candidate findings must carry
    a non-empty `affected_rules`. Backfilled in the audit pipeline to
    the names of attached Web ACLs."""
    db = mongomock.MongoClient()["ruleiq_phase5_3_1_bypass"]
    db_mod.set_test_db(db)

    def fake_load(*_a, **_kw):
        return [{
            "rule_name": "DummyAllow", "web_acl_name": "ruleiq-cf-acl",
            "priority": 0, "action": "ALLOW", "rule_kind": "custom",
            "statement_json": {}, "hit_count": 1, "count_mode_hits": 0,
            "last_fired": None, "sample_uris": [],
            "fms_managed": False, "override_action": None,
            "managed_rule_overrides": [],
        }], {
            "data_source": "fixture", "fms_visibility": None,
            "logging_available": True, "web_acl_count": 2,
            "web_acls": [
                {"name": "ruleiq-cf-acl", "scope": "CLOUDFRONT",
                 "arn": "arn:cf", "attached_resources": ["arn:cfd"], "attached": True},
                {"name": "ruleiq-regional-acl", "scope": "REGIONAL",
                 "arn": "arn:r", "attached_resources": ["arn:alb"], "attached": True},
                {"name": "orphan-acl", "scope": "REGIONAL",
                 "arn": "arn:o", "attached_resources": [], "attached": False},
            ],
            "orphan_acl_names": {"orphan-acl"},
            "suspicious_requests": [{"id": 1}],
        }
    monkeypatch.setattr(audit_mod, "_load_rules_from_fixtures", fake_load)
    monkeypatch.setenv("DEMO_MODE", "true")

    def fake_pipeline(rules, suspicious_requests=None, **_kw):
        return {
            "rules": [],
            "findings": [{
                "type": "bypass_candidate", "severity": "high",
                "title": "Possible WAF bypass: shellshock",
                "description": "shellshock UA reached origin",
                "recommendation": "Enable KnownBadInputs",
                "affected_rules": [],  # log-derived, intentionally empty
                "confidence": 0.95,
                "evidence": "log-sample",
            }],
        }
    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline", fake_pipeline)

    audit_id = audit_mod.create_audit_run(
        db=db, account_id="123456789012", role_arn=None,
        region="us-east-1", log_window_days=30, external_id=None,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    bypasses = list(db["findings"].find({
        "audit_run_id": audit_id, "type": "bypass_candidate",
    }))
    assert len(bypasses) == 1
    affected = bypasses[0]["affected_rules"]
    assert affected, "bypass_candidate affected_rules must be non-empty"
    # Must include the attached ACL names; the orphan is excluded
    # (it's not on the request path).
    assert "ruleiq-cf-acl" in affected
    assert "ruleiq-regional-acl" in affected
    assert "orphan-acl" not in affected


# --- Fix 4 — UTC `Z` suffix on audit-run timestamps -----------------------


def test_audit_run_timestamps_serialize_with_Z_suffix(monkeypatch):
    """Phase 5.3.1 acceptance #2 — GET /api/audits/<id> returns
    `created_at`, `started_at`, `completed_at` all ending in `Z`."""
    from main import app
    db = mongomock.MongoClient()["ruleiq_phase5_3_1_ts"]
    db_mod.set_test_db(db)

    def fake_load(*_a, **_kw):
        return [{
            "rule_name": "DummyAllow", "web_acl_name": "acl-x",
            "priority": 0, "action": "ALLOW", "rule_kind": "custom",
            "statement_json": {}, "hit_count": 1, "count_mode_hits": 0,
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
                        lambda *_a, **_kw: {"rules": [], "findings": []})

    audit_id = audit_mod.create_audit_run(
        db=db, account_id="123456789012", role_arn=None,
        region="us-east-1", log_window_days=30, external_id=None,
    )
    audit_mod.run_audit_pipeline(audit_id, db)

    client = TestClient(app)
    resp = client.get(f"/api/audits/{audit_id}")
    assert resp.status_code == 200
    body = resp.json()
    iso_z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
    for field in ("created_at", "completed_at"):
        assert iso_z.match(body[field]), (
            f"{field}={body[field]!r} does not match ISO-8601 Z"
        )


# --- Fix 2 — PDF renderer reads FLAT keys ---------------------------------


def test_pdf_renders_remediation_from_flat_keys_not_nested():
    """The PDF's Remediation block must render directly from the
    finding's `suggested_actions` / `verify_by` / `disclaimer` keys
    (Phase ≥5.3.1 shape)."""
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
    findings = [{
        "type": "bypass_candidate", "severity": "high",
        "title": "Possible WAF bypass", "description": "shellshock",
        "recommendation": "x", "affected_rules": ["acl-x"],
        "confidence": 0.9, "severity_score": 80,
        "suggested_actions": [
            "Action one — use AWSManagedRulesKnownBadInputsRuleSet.",
            "Action two — deploy in COUNT first.",
        ],
        "verify_by": "Replay the captured request and confirm 403.",
        "disclaimer": "EdgePosture does not generate WAF rules.",
    }]
    pdf_bytes = render_audit_pdf(run, [], findings)
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
    assert "Suggested actions" in text
    assert "AWSManagedRulesKnownBadInputsRuleSet" in text
    assert "Verify by" in text
    assert "Replay the captured request" in text
    assert "EdgePosture does not generate WAF rules" in text


def test_pdf_renderer_falls_back_when_no_remediation_present(caplog):
    """Legacy audits (no remediation, no flat keys) still render and emit
    a WARNING log instead of crashing."""
    from pypdf import PdfReader
    from services.pdf_report import render_audit_pdf
    import logging
    import datetime as _dt

    run = {
        "_id": "x", "account_id": "123456789012", "data_source": "aws",
        "rule_count": 0, "web_acl_count": 0,
        "estimated_waste_usd": 0.0, "estimated_waste_breakdown": [],
        "created_at": _dt.datetime.now(_dt.timezone.utc),
        "completed_at": _dt.datetime.now(_dt.timezone.utc),
        "scopes": ["REGIONAL"], "web_acls": [],
    }
    findings = [{
        "type": "bypass_candidate", "severity": "high",
        "title": "Legacy finding", "description": "x",
        "recommendation": "Use a managed rule group.",
        "affected_rules": [], "confidence": 0.9, "severity_score": 80,
    }]
    with caplog.at_level(logging.WARNING):
        pdf_bytes = render_audit_pdf(run, [], findings)
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
    # AI recommendation rendered as fallback.
    assert "Use a managed rule group" in text
    assert any("no remediation fields" in r.getMessage() for r in caplog.records), (
        "expected fallback WARNING log"
    )
