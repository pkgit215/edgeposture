"""Phase 4 — PDF audit report tests."""
from __future__ import annotations

import io
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import mongomock
import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"

from services import db as db_mod  # noqa: E402
from services import pdf_report as pdf_mod  # noqa: E402
import main  # noqa: E402


# ---- fixtures ---------------------------------------------------------------


def _sample_audit_run(account_id: str = "111122223333", status: str = "complete"):
    return {
        "_id": "audit-phase4-1",
        "account_id": account_id,
        "region": "us-east-1",
        "role_arn": f"arn:aws:iam::{account_id}:role/RuleIQAuditRole",
        "external_id": "abc12345abc12345abc12345abc12345",
        "status": status,
        "data_source": "aws",
        "rule_count": 8,
        "web_acl_count": 1,
        "log_window_days": 30,
        "log_source": "CloudWatch Logs",
        "scope": "REGIONAL",
        "estimated_waste_usd": 137,
        "created_at": datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc),
        "started_at": datetime(2026, 5, 1, 12, 0, 5, tzinfo=timezone.utc),
        "completed_at": datetime(2026, 5, 1, 12, 0, 41, tzinfo=timezone.utc),
        "estimated_waste_breakdown": [
            {"rule_name": "DeadGeoBlockEU", "monthly_usd": 91},
            {"rule_name": "DeadCustomRule_X", "monthly_usd": 46},
        ],
    }


def _sample_rules():
    return [
        {
            "rule_name": "BlockKnownMaliciousIPs",
            "web_acl_name": "ruleiq-prod-acl",
            "priority": 10,
            "action": "BLOCK",
            "hit_count": 18432,
            "last_fired": "2026-04-30T14:23:11Z",
            "fms_managed": False,
        },
        {
            "rule_name": "DeadGeoBlockEU",
            "web_acl_name": "ruleiq-prod-acl",
            "priority": 30,
            "action": "BLOCK",
            "hit_count": 0,
            "last_fired": None,
            "fms_managed": False,
        },
        {
            "rule_name": "FMSManagedCommonRules",
            "web_acl_name": "ruleiq-prod-acl",
            "priority": 5,
            "action": "BLOCK",
            "hit_count": 0,
            "last_fired": None,
            "fms_managed": True,
            "override_action": "None",
        },
        {
            "rule_name": "ConflictingAllow",
            "web_acl_name": "ruleiq-prod-acl",
            "priority": 90,
            "action": "ALLOW",
            "hit_count": 4,
            "last_fired": "2026-04-29T08:00:00Z",
            "fms_managed": False,
        },
    ]


def _sample_findings():
    return [
        {
            "audit_run_id": "audit-phase4-1",
            "type": "dead_rule",
            "severity": "medium",
            "severity_score": 60,
            "affected_rules": ["DeadGeoBlockEU"],
            "title": "EU geo-block fired 0 times in 30 days",
            "description": "DeadGeoBlockEU has not produced a single match.",
            "recommendation": "Remove or convert to COUNT mode for one cycle.",
            "confidence": 0.93,
        },
        {
            "audit_run_id": "audit-phase4-1",
            "type": "bypass_candidate",
            "severity": "high",
            "severity_score": 85,
            "affected_rules": ["BlockKnownMaliciousIPs"],
            "title": "Suspicious low hit rate on critical IP block",
            "description": "Hit rate has dropped 70% week-over-week.",
            "recommendation": "Investigate IP set freshness.",
            "confidence": 0.78,
        },
        {
            "audit_run_id": "audit-phase4-1",
            "type": "conflict",
            "severity": "medium",
            "severity_score": 55,
            "affected_rules": ["BlockKnownMaliciousIPs", "ConflictingAllow"],
            "title": "ALLOW after BLOCK on overlapping path",
            "description": "Two rules contradict on /api/v1/*.",
            "recommendation": "Re-order or remove ConflictingAllow.",
            "confidence": 0.66,
        },
        {
            "audit_run_id": "audit-phase4-1",
            "type": "quick_win",
            "severity": "low",
            "severity_score": 20,
            "affected_rules": ["DeadGeoBlockEU"],
            "title": "Easy removal candidate",
            "description": "No traffic, no conflicts.",
            "recommendation": "Delete next change window.",
            "confidence": 0.9,
        },
        {
            "audit_run_id": "audit-phase4-1",
            "type": "fms_review",
            "severity": "low",
            "severity_score": 15,
            "affected_rules": ["FMSManagedCommonRules"],
            "title": "FMS-managed rule with zero hits",
            "description": "Centrally controlled — no customer-side action.",
            "recommendation": "Flag for FMS admin review.",
            "confidence": 0.95,
        },
    ]


# ---- pure renderer ----------------------------------------------------------


def test_render_audit_pdf_returns_pdf_bytes():
    pdf = pdf_mod.render_audit_pdf(
        _sample_audit_run(), _sample_rules(), _sample_findings()
    )
    assert isinstance(pdf, (bytes, bytearray))
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 5_000


def test_render_audit_pdf_contains_expected_text():
    pdf_bytes = pdf_mod.render_audit_pdf(
        _sample_audit_run(), _sample_rules(), _sample_findings()
    )
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(p.extract_text() or "" for p in reader.pages)

    # full account ID is present (NOT masked — per spec).
    assert "111122223333" in text

    # audit date — at least the year-month-day portion of completed_at.
    assert "2026-05-01" in text

    # all 4 finding-type group headers present.
    assert "Dead rules" in text
    assert "Bypass candidates" in text
    assert "Rule conflicts" in text
    assert "Quick wins" in text

    # FMS section also present (we have one fms_review finding).
    assert "FMS-managed review items" in text or "FMS-managed" in text

    # zero-hit rule should be labelled.
    assert "Never fired" in text


def test_pdf_contains_what_was_tested_provenance_section():
    """Cover-page 'What was tested' callout is present with all 5 fields."""
    pdf_bytes = pdf_mod.render_audit_pdf(
        _sample_audit_run(), _sample_rules(), _sample_findings()
    )
    text = "\n".join(
        (p.extract_text() or "")
        for p in PdfReader(io.BytesIO(pdf_bytes)).pages
    )
    assert "What was tested" in text
    assert "Log window" in text
    assert "30 days" in text
    assert "Log source" in text
    assert "CloudWatch Logs" in text
    assert "Web ACLs scanned" in text
    assert "Rules analyzed" in text
    assert "Scope" in text
    assert "REGIONAL" in text


def test_pdf_executive_summary_does_not_repeat_waste_figure():
    """Waste $ figure must appear exactly once — in the cover-page summary
    stats card. The duplicate at the bottom of the Executive Summary was
    removed in the polish pass."""
    pdf_bytes = pdf_mod.render_audit_pdf(
        _sample_audit_run(), _sample_rules(), _sample_findings()
    )
    text = "\n".join(
        (p.extract_text() or "")
        for p in PdfReader(io.BytesIO(pdf_bytes)).pages
    )
    # "$137 / month" headline string occurs once on the cover page only.
    assert text.count("$137 / month") == 1
    # And the dropped sentence is gone.
    assert "dead-rule findings contributing" not in text


def test_pdf_inventory_table_uses_iso_short_form_for_last_fired():
    """Last-Fired column must render as YYYY-MM-DD HH:MM UTC, not relative."""
    pdf_bytes = pdf_mod.render_audit_pdf(
        _sample_audit_run(), _sample_rules(), _sample_findings()
    )
    text = "\n".join(
        (p.extract_text() or "")
        for p in PdfReader(io.BytesIO(pdf_bytes)).pages
    )
    # Sample rules have last_fired "2026-04-30T14:23:11Z" → "2026-04-30 14:23 UTC"
    assert "2026-04-30 14:23 UTC" in text


# ---- endpoint ---------------------------------------------------------------


@pytest.fixture()
def db():
    mock = mongomock.MongoClient()["ruleiq_phase4"]
    db_mod.set_test_db(mock)
    yield mock
    db_mod.clear_test_db()


@pytest.fixture()
def client(db) -> TestClient:
    return TestClient(main.app)


def _seed(db, status: str = "complete") -> str:
    run = _sample_audit_run(status=status)
    db["audit_runs"].insert_one(run)
    for r in _sample_rules():
        db["rules"].insert_one({**r, "audit_run_id": run["_id"]})
    for f in _sample_findings():
        db["findings"].insert_one(f)
    return run["_id"]


def test_pdf_endpoint_returns_200_for_complete_audit(client, db):
    audit_id = _seed(db, status="complete")
    resp = client.get(f"/api/audits/{audit_id}/report.pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    cd = resp.headers["content-disposition"]
    assert "attachment" in cd
    assert "ruleiq-audit-111122223333-" in cd
    assert cd.endswith('.pdf"')
    body = resp.content
    assert body[:5] == b"%PDF-"
    assert len(body) > 5_000


def test_pdf_endpoint_returns_409_for_pending_audit(client, db):
    audit_id = _seed(db, status="running")
    resp = client.get(f"/api/audits/{audit_id}/report.pdf")
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "Audit not yet complete"
    assert body["status"] == "running"


def test_pdf_endpoint_returns_404_for_missing_audit(client):
    resp = client.get("/api/audits/does-not-exist/report.pdf")
    assert resp.status_code == 404


def test_critical_routes_are_registered():
    """Defensive: catches the 'router defined but not included' class of bug
    that produced the Phase 4 production 404 false alarm."""
    paths = {r.path for r in main.app.routes}
    expected = {
        "/api/health",
        "/api/setup-info",
        "/api/audits",
        "/api/audits/{audit_id}",
        "/api/audits/{audit_id}/rules",
        "/api/audits/{audit_id}/findings",
        "/api/audits/{audit_id}/report.pdf",
    }
    missing = expected - paths
    assert not missing, f"Missing critical routes: {missing}"
