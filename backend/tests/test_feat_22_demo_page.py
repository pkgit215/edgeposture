"""Feat #22 — `/api/demo/*` public demo endpoints.

The demo serves the pre-built fixture at `backend/demo/demo_audit.json`
and the matching PDF at `backend/demo/demo_audit.pdf`. The endpoints are
public (no auth, no role assumption) and read-only.
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

from fastapi.testclient import TestClient

import main as main_mod


client = TestClient(main_mod.app)


def test_demo_audit_endpoint_returns_combined_payload():
    resp = client.get("/api/demo/audit")
    assert resp.status_code == 200
    body = resp.json()
    # Combined `{audit, rules, findings}` envelope.
    for key in ("audit", "rules", "findings"):
        assert key in body, f"missing top-level key: {key}"
    # Audit envelope carries the demo account stub, not a real one.
    assert body["audit"]["account_id"] == "123456789012"
    # Enterprise-scale shape: 4 Web ACLs, 52 rules, $186/mo waste.
    assert body["audit"]["web_acl_count"] == 4, body["audit"]["web_acl_count"]
    assert body["audit"]["rule_count"] == 52, body["audit"]["rule_count"]
    assert body["audit"]["estimated_waste_usd"] == 186.00, (
        body["audit"]["estimated_waste_usd"]
    )
    assert len(body["rules"]) == 52, len(body["rules"])
    assert len(body["audit"]["web_acls"]) == 4, len(body["audit"]["web_acls"])
    # 14 findings; 4H / 5M / 5L distribution.
    assert len(body["findings"]) == 14, len(body["findings"])
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in body["findings"]:
        counts[f["severity"]] += 1
    assert counts == {"high": 4, "medium": 5, "low": 5}, counts


def test_demo_audit_contains_multiple_finding_types():
    """The demo must showcase the full breadth of finding types
    RuleIQ ships — at least 8 distinct types across security,
    operational, and cost categories."""
    body = client.get("/api/demo/audit").json()
    types = {f["type"] for f in body["findings"]}
    assert len(types) >= 8, f"demo too thin, only types: {sorted(types)}"
    # Spec-pinned types that the marketing/PR review must see.
    expected = {
        "bypass_candidate", "dead_rule", "conflict", "quick_win",
        "fms_review", "count_mode_with_hits", "count_mode_high_volume",
        "managed_rule_override_count", "orphaned_web_acl",
    }
    assert expected <= types, (
        f"missing required types: {sorted(expected - types)}"
    )


def test_demo_audit_has_no_real_account_id_leaked():
    """Static-fixture guarantee: real-account / real-repo substrings must
    NOT leak into the committed demo payload. `acmecorp.com` is the
    fictional brand and is explicitly allowed."""
    resp = client.get("/api/demo/audit")
    for forbidden in ("371126261144", "aitrading.ninja", "pkgit215",
                       "ruleiq-test-acl"):
        assert forbidden not in resp.text, f"forbidden string leaked: {forbidden}"
    # Sanity — the fictional brand is preserved (proves the test runs
    # against the rich fixture, not a stripped one).
    assert "acmecorp.com" in resp.text


def test_demo_report_pdf_endpoint_returns_pdf_bytes():
    resp = client.get("/api/demo/report.pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/pdf")
    # Inline disposition — open in-browser preview, not a forced download.
    assert "ruleiq-demo-audit.pdf" in resp.headers.get(
        "content-disposition", ""
    )
    # Minimum sanity: a real PDF starts with `%PDF-`.
    assert resp.content[:5] == b"%PDF-"


def test_demo_endpoints_are_unauthenticated():
    """Demo endpoints must not require any header — they are public so
    we can link the marketing site straight at them."""
    resp = client.get("/api/demo/audit", headers={})
    assert resp.status_code == 200
    resp_pdf = client.get("/api/demo/report.pdf", headers={})
    assert resp_pdf.status_code == 200


def test_demo_findings_carry_remediation_blocks():
    """Phase 5.3.x — every persisted finding ships with Impact +
    suggested_actions. The demo must preserve that contract so the
    public PR review sees what real audits look like."""
    body = client.get("/api/demo/audit").json()
    for f in body["findings"]:
        assert f.get("impact"), f"finding {f['type']} missing impact"
        assert (f.get("suggested_actions") or []), (
            f"finding {f['type']} missing suggested_actions"
        )
