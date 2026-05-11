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
    assert isinstance(body["rules"], list) and len(body["rules"]) > 0
    assert isinstance(body["findings"], list) and len(body["findings"]) > 0


def test_demo_audit_contains_multiple_finding_types():
    """The demo must showcase at least 4 distinct finding types so the
    `/demo` page demonstrates the product surface area, not a single
    finding category."""
    body = client.get("/api/demo/audit").json()
    types = {f["type"] for f in body["findings"]}
    assert len(types) >= 4, f"demo too thin, only types: {sorted(types)}"
    # The hero finding for a security demo: a bypass candidate.
    assert "bypass_candidate" in types, (
        f"demo missing bypass_candidate; types: {sorted(types)}"
    )


def test_demo_audit_has_no_real_account_id_leaked():
    """Static-fixture guarantee: the real 371126261144 account id MUST
    NOT leak into the committed demo payload."""
    resp = client.get("/api/demo/audit")
    assert "371126261144" not in resp.text


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
