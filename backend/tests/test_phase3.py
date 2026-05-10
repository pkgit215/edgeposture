"""Phase 3 tests — findings_count aggregation + SPA static mount.

Strategy:
- mongomock for the audit/findings collections (same hybrid as Phase 1/2).
- For the SPA mount we re-import `main` against a temp `RULEIQ_SPA_DIST`
  directory that contains a fake index.html, and verify both:
    - GET /          → returns the fake SPA index
    - GET /api/health → still returns JSON (mount must not shadow API routes)
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import mongomock
import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"

from services import audit as audit_mod  # noqa: E402
from services import db as db_mod  # noqa: E402
import main  # noqa: E402


# ---------- findings_count ---------------------------------------------------


@pytest.fixture()
def db():
    mock = mongomock.MongoClient()["ruleiq_phase3"]
    db_mod.set_test_db(mock)
    yield mock
    db_mod.clear_test_db()


@pytest.fixture()
def client(db) -> TestClient:
    return TestClient(main.app)


def _seed_audit_with_findings(db, findings_count: int) -> str:
    audit_id = audit_mod.create_audit_run(
        db, "111122223333", None, "us-east-1", 30
    )
    db["audit_runs"].update_one(
        {"_id": audit_id},
        {"$set": {"status": "complete", "rule_count": 10, "data_source": "fixture"}},
    )
    if findings_count:
        db["findings"].insert_many(
            [
                {
                    "audit_run_id": audit_id,
                    "type": "dead_rule",
                    "severity": "medium",
                    "severity_score": 50,
                    "affected_rules": ["r"],
                    "title": "t",
                    "description": "d",
                    "recommendation": "r",
                    "confidence": 0.9,
                }
                for _ in range(findings_count)
            ]
        )
    return audit_id


def test_list_audits_includes_findings_count(client, db):
    a1 = _seed_audit_with_findings(db, findings_count=3)
    a2 = _seed_audit_with_findings(db, findings_count=0)

    resp = client.get("/api/audits")
    assert resp.status_code == 200
    rows = resp.json()
    by_id = {r["id"]: r for r in rows}
    assert by_id[a1]["findings_count"] == 3
    assert by_id[a2]["findings_count"] == 0


def test_list_audits_findings_count_uses_single_aggregate(client, db, monkeypatch):
    """No N+1: must NOT call count_documents per audit when listing."""
    for _ in range(5):
        _seed_audit_with_findings(db, findings_count=2)

    real_count = db["findings"].count_documents
    calls = {"n": 0}

    def spy(*a, **kw):
        calls["n"] += 1
        return real_count(*a, **kw)

    monkeypatch.setattr(db["findings"], "count_documents", spy)
    resp = client.get("/api/audits")
    assert resp.status_code == 200
    # 5 audits, 2 findings each → list endpoint must do 0 count_documents calls
    # (it uses an aggregate $group instead).
    assert calls["n"] == 0


def test_get_audit_includes_findings_count(client, db):
    audit_id = _seed_audit_with_findings(db, findings_count=4)
    resp = client.get(f"/api/audits/{audit_id}")
    assert resp.status_code == 200
    assert resp.json()["findings_count"] == 4


# ---------- SPA mount --------------------------------------------------------


def test_spa_mount_serves_index_when_dist_present(tmp_path, monkeypatch):
    """If a built SPA exists at RULEIQ_SPA_DIST, GET / returns its index.html
    while /api/* routes still respond as JSON."""
    dist = tmp_path / "static"
    dist.mkdir()
    (dist / "index.html").write_text(
        "<!doctype html><html><body>RULEIQ_SPA_OK</body></html>"
    )
    (dist / "assets").mkdir()
    (dist / "assets" / "app.js").write_text("// fake bundle")

    monkeypatch.setenv("RULEIQ_SPA_DIST", str(dist))
    # Force-reload the module so the mount runs against the new dist dir.
    import main as _main  # noqa: PLC0415

    fresh = importlib.reload(_main)
    client = TestClient(fresh.app)

    # SPA root
    resp = client.get("/")
    assert resp.status_code == 200, resp.text
    assert "RULEIQ_SPA_OK" in resp.text
    assert "text/html" in resp.headers.get("content-type", "")

    # Asset
    asset = client.get("/assets/app.js")
    assert asset.status_code == 200
    assert "fake bundle" in asset.text

    # SPA fallback for unknown frontend route
    fallback = client.get("/some/deep/spa/route")
    assert fallback.status_code == 200
    assert "RULEIQ_SPA_OK" in fallback.text


def test_spa_mount_does_not_shadow_api_routes(tmp_path, monkeypatch):
    dist = tmp_path / "static"
    dist.mkdir()
    (dist / "index.html").write_text("<html>SPA</html>")

    monkeypatch.setenv("RULEIQ_SPA_DIST", str(dist))
    import main as _main  # noqa: PLC0415

    fresh = importlib.reload(_main)
    db_mod.set_test_db(mongomock.MongoClient()["ruleiq_phase3_spa"])
    try:
        client = TestClient(fresh.app)
        h = client.get("/api/health")
        assert h.status_code == 200
        body = h.json()
        assert body["status"] == "ok"
        assert body["phase"] == "3"

        oa = client.get("/api/openapi.json")
        assert oa.status_code == 200
        assert oa.json()["info"]["title"] == "RuleIQ"
    finally:
        db_mod.clear_test_db()


def test_spa_mount_is_skipped_when_dist_missing(tmp_path, monkeypatch):
    """No dist → root returns 404, API still works."""
    monkeypatch.setenv("RULEIQ_SPA_DIST", str(tmp_path / "nope"))
    import main as _main  # noqa: PLC0415

    fresh = importlib.reload(_main)
    db_mod.set_test_db(mongomock.MongoClient()["ruleiq_phase3_nodist"])
    try:
        client = TestClient(fresh.app)
        assert client.get("/api/health").status_code == 200
        assert client.get("/").status_code == 404
    finally:
        db_mod.clear_test_db()



# ---------- Phase 3 hot-fix v2: deterministic per-account ExternalId --------


def test_compute_external_id_is_deterministic(monkeypatch):
    """Same secret + same account_id => same ExternalId, every call."""
    from services import secrets as _secrets  # noqa: PLC0415
    from services import tenant as _tenant  # noqa: PLC0415

    monkeypatch.setenv("EXTERNAL_ID_SECRET", "a" * 64)
    _secrets._reset_cache_for_tests()

    a = _tenant.compute_external_id("123456789012")
    b = _tenant.compute_external_id("123456789012")
    c = _tenant.compute_external_id("123456789012")
    assert a == b == c
    assert len(a) == 32
    # Hex characters only.
    int(a, 16)


def test_compute_external_id_depends_on_account_id(monkeypatch):
    from services import secrets as _secrets  # noqa: PLC0415
    from services import tenant as _tenant  # noqa: PLC0415

    monkeypatch.setenv("EXTERNAL_ID_SECRET", "a" * 64)
    _secrets._reset_cache_for_tests()

    a = _tenant.compute_external_id("123456789012")
    b = _tenant.compute_external_id("999988887777")
    assert a != b


def test_compute_external_id_depends_on_secret(monkeypatch):
    from services import secrets as _secrets  # noqa: PLC0415
    from services import tenant as _tenant  # noqa: PLC0415

    monkeypatch.setenv("EXTERNAL_ID_SECRET", "a" * 64)
    _secrets._reset_cache_for_tests()
    a = _tenant.compute_external_id("123456789012")

    monkeypatch.setenv("EXTERNAL_ID_SECRET", "b" * 64)
    _secrets._reset_cache_for_tests()
    b = _tenant.compute_external_id("123456789012")

    assert a != b


def test_compute_external_id_rejects_invalid_account_id(monkeypatch):
    from services import secrets as _secrets  # noqa: PLC0415
    from services import tenant as _tenant  # noqa: PLC0415

    monkeypatch.setenv("EXTERNAL_ID_SECRET", "a" * 64)
    _secrets._reset_cache_for_tests()

    import pytest as _pytest  # noqa: PLC0415

    for bad in ["", "abc", "12345", "1234567890123", "12345678901a"]:
        with _pytest.raises(ValueError):
            _tenant.compute_external_id(bad)


def test_setup_info_no_account_id_returns_null_external_id(client):
    resp = client.get("/api/setup-info")
    assert resp.status_code == 200
    body = resp.json()
    assert body["external_id"] is None
    assert body["cfn_quick_create_url"] is None
    assert body["account_id"] is None
    # Policy + template URL still served so the UI can render Step 0 hints.
    assert body["inline_iam_json"]["Version"] == "2012-10-17"
    assert body["cfn_template_url"].endswith("/customer-role.yaml")


def test_setup_info_invalid_account_id_returns_null_external_id(client):
    body = client.get("/api/setup-info?account_id=not-an-account").json()
    assert body["external_id"] is None
    assert body["cfn_quick_create_url"] is None
    body = client.get("/api/setup-info?account_id=1234").json()
    assert body["external_id"] is None


def test_setup_info_same_account_id_returns_same_external_id(client):
    a = client.get("/api/setup-info?account_id=123456789012").json()["external_id"]
    b = client.get("/api/setup-info?account_id=123456789012").json()["external_id"]
    assert a == b
    assert len(a) == 32


def test_setup_info_different_account_ids_return_different_external_ids(client):
    a = client.get("/api/setup-info?account_id=123456789012").json()["external_id"]
    b = client.get("/api/setup-info?account_id=999988887777").json()["external_id"]
    assert a != b
    assert len(a) == 32 and len(b) == 32


def test_audit_post_recomputes_external_id_server_side(client, db, monkeypatch):
    """The submitted body must NOT contain external_id. The server recomputes
    it from account_id and passes it to the audit pipeline."""
    captured = {}

    from services import audit as _audit_mod  # noqa: PLC0415

    real_create = _audit_mod.create_audit_run

    def spy(**kwargs):
        captured.update(kwargs)
        # Don't actually persist — return a fake id.
        return "spy-audit-id"

    monkeypatch.setattr(_audit_mod, "create_audit_run", spy)
    monkeypatch.setattr(_audit_mod, "run_audit_pipeline", lambda *a, **kw: None)

    expected = client.get(
        "/api/setup-info?account_id=123456789012"
    ).json()["external_id"]

    resp = client.post(
        "/api/audits",
        json={
            "account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/RuleIQAuditRole",
            "region": "us-east-1",
        },
    )
    assert resp.status_code == 202, resp.text
    assert captured["external_id"] == expected
    # Sanity: real create_audit_run path still wired up correctly.
    assert real_create is not _audit_mod.create_audit_run


def test_audit_post_ignores_client_supplied_external_id(client, db, monkeypatch):
    """Even if a malicious client sends external_id, it is ignored — the
    server only ever uses the HMAC value."""
    captured = {}

    from services import audit as _audit_mod  # noqa: PLC0415

    monkeypatch.setattr(
        _audit_mod, "create_audit_run", lambda **kw: (captured.update(kw) or "id")
    )
    monkeypatch.setattr(_audit_mod, "run_audit_pipeline", lambda *a, **kw: None)

    expected = client.get(
        "/api/setup-info?account_id=123456789012"
    ).json()["external_id"]

    resp = client.post(
        "/api/audits",
        json={
            "account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/RuleIQAuditRole",
            "external_id": "client-supplied-attack-value",
            "region": "us-east-1",
        },
    )
    assert resp.status_code == 202
    # Server recomputed and OVERWROTE whatever the client sent.
    assert captured["external_id"] == expected
    assert captured["external_id"] != "client-supplied-attack-value"


def test_audit_post_demo_mode_skips_external_id(client, db, monkeypatch):
    """When role_arn is None (demo path), external_id is None — no STS call."""
    captured = {}

    from services import audit as _audit_mod  # noqa: PLC0415

    monkeypatch.setattr(
        _audit_mod, "create_audit_run", lambda **kw: (captured.update(kw) or "id")
    )
    monkeypatch.setattr(_audit_mod, "run_audit_pipeline", lambda *a, **kw: None)

    resp = client.post(
        "/api/audits",
        json={
            "account_id": "111122223333",
            "role_arn": None,
            "region": "us-east-1",
        },
    )
    assert resp.status_code == 202
    assert captured["external_id"] is None


def test_audit_post_real_aws_rejects_invalid_account_id(client):
    # Pydantic enforces 12-digit length; non-digits won't reach our validator.
    # But valid-length-but-non-numeric is caught by us:
    resp = client.post(
        "/api/audits",
        json={
            "account_id": "abcdefghijkl",  # 12 chars but non-numeric
            "role_arn": "arn:aws:iam::000000000000:role/RuleIQAuditRole",
            "region": "us-east-1",
        },
    )
    assert resp.status_code == 400
    assert "account_id" in resp.json()["detail"]

