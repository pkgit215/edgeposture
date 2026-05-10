"""Phase 4.5 — Account memory + Re-run."""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from pathlib import Path

import mongomock
import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)

from services import db as db_mod  # noqa: E402
from services import secrets as secrets_mod  # noqa: E402
import main  # noqa: E402

ACCOUNT = "111122223333"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/RuleIQAuditRole"


@pytest.fixture()
def db():
    secrets_mod._reset_cache_for_tests()
    mock = mongomock.MongoClient()["ruleiq_phase45"]
    db_mod.set_test_db(mock)
    yield mock
    db_mod.clear_test_db()


@pytest.fixture()
def client(db, monkeypatch) -> TestClient:
    # Stub the audit pipeline so background tasks never reach STS / OpenAI.
    from services import audit as audit_mod  # noqa: PLC0415

    monkeypatch.setattr(audit_mod, "run_audit_pipeline", lambda *a, **kw: None)
    return TestClient(main.app)


# ---- POST /api/audits upserts the account ----------------------------------


def test_post_audits_creates_account_record_on_first_call(client, db):
    resp = client.post(
        "/api/audits",
        json={"account_id": ACCOUNT, "role_arn": ROLE_ARN, "region": "us-east-1"},
    )
    assert resp.status_code == 202

    doc = db["accounts"].find_one({"account_id": ACCOUNT})
    assert doc is not None
    assert doc["account_id"] == ACCOUNT
    assert doc["role_arn"] == ROLE_ARN
    assert isinstance(doc["created_at"], datetime)
    assert isinstance(doc["last_audit_at"], datetime)


def test_post_audits_upserts_account_and_advances_last_audit_at(client, db):
    client.post(
        "/api/audits",
        json={"account_id": ACCOUNT, "role_arn": ROLE_ARN, "region": "us-east-1"},
    )
    first = db["accounts"].find_one({"account_id": ACCOUNT})
    created_at_first = first["created_at"]
    last_at_first = first["last_audit_at"]

    time.sleep(0.01)

    client.post(
        "/api/audits",
        json={"account_id": ACCOUNT, "role_arn": ROLE_ARN, "region": "us-east-1"},
    )
    second = db["accounts"].find_one({"account_id": ACCOUNT})
    # created_at MUST be preserved ($setOnInsert).
    assert second["created_at"] == created_at_first
    # last_audit_at MUST advance.
    assert second["last_audit_at"] >= last_at_first


def test_last_audit_at_strictly_advances_across_subsequent_audits(client, db):
    """Regression for v4.5.1: `last_audit_at` was stuck on the first value
    because it lived in `$setOnInsert`. This test asserts the field strictly
    advances between successive POST /api/audits calls AND that GET
    /api/accounts/{id} surfaces the new value."""
    r1 = client.post(
        "/api/audits",
        json={"account_id": ACCOUNT, "role_arn": ROLE_ARN, "region": "us-east-1"},
    )
    assert r1.status_code == 202
    t1 = client.get(f"/api/accounts/{ACCOUNT}").json()["last_audit_at"]
    assert t1 is not None

    time.sleep(0.05)

    r2 = client.post(
        "/api/audits",
        json={"account_id": ACCOUNT, "role_arn": ROLE_ARN, "region": "us-east-1"},
    )
    assert r2.status_code == 202
    t2 = client.get(f"/api/accounts/{ACCOUNT}").json()["last_audit_at"]
    assert t2 is not None
    # ISO-8601 strings sort lexicographically by time when both are UTC.
    assert t2 > t1, f"last_audit_at did not advance: {t1} → {t2}"


def test_last_audit_at_strictly_advances_on_rerun(client, db):
    """Same regression on the /api/audits/rerun path."""
    client.post(
        "/api/audits",
        json={"account_id": ACCOUNT, "role_arn": ROLE_ARN, "region": "us-east-1"},
    )
    t1 = client.get(f"/api/accounts/{ACCOUNT}").json()["last_audit_at"]

    time.sleep(0.05)

    rerun = client.post(
        "/api/audits/rerun", json={"account_id": ACCOUNT, "region": "us-east-1"}
    )
    assert rerun.status_code == 202
    t2 = client.get(f"/api/accounts/{ACCOUNT}").json()["last_audit_at"]
    assert t2 > t1, f"rerun did not advance last_audit_at: {t1} → {t2}"


def test_post_audits_demo_mode_does_not_set_role_arn(client, db):
    """No role_arn in request → existing audit.py upserts an account row
    with role_arn=None. /api/audits/rerun on this account must 404."""
    resp = client.post(
        "/api/audits",
        json={"account_id": ACCOUNT, "region": "us-east-1"},
    )
    assert resp.status_code == 202
    doc = db["accounts"].find_one({"account_id": ACCOUNT})
    # The doc may exist (audit.py creates it) but role_arn must be empty.
    if doc:
        assert not doc.get("role_arn")
    # Re-run must reject — there is no saved role.
    rerun = client.post(
        "/api/audits/rerun", json={"account_id": ACCOUNT, "region": "us-east-1"}
    )
    assert rerun.status_code == 404


# ---- GET /api/accounts/{id} -------------------------------------------------


def test_get_account_returns_404_when_unknown(client, db):
    resp = client.get(f"/api/accounts/{ACCOUNT}")
    assert resp.status_code == 404


def test_get_account_returns_data_after_audit(client, db):
    client.post(
        "/api/audits",
        json={"account_id": ACCOUNT, "role_arn": ROLE_ARN, "region": "us-east-1"},
    )
    resp = client.get(f"/api/accounts/{ACCOUNT}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["account_id"] == ACCOUNT
    assert body["role_arn"] == ROLE_ARN
    assert body["created_at"]
    assert body["last_audit_at"]


def test_get_account_invalid_id_returns_422(client):
    for bad in ["abc", "12345", "1234567890123", "12345678901a"]:
        assert client.get(f"/api/accounts/{bad}").status_code == 422


# ---- GET /api/accounts ------------------------------------------------------


def test_list_accounts_empty(client):
    resp = client.get("/api/accounts")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_accounts_sorted_by_last_audit_desc(client, db):
    a, b = "111122223333", "999988887777"
    client.post(
        "/api/audits",
        json={"account_id": a, "role_arn": f"arn:aws:iam::{a}:role/X"},
    )
    time.sleep(0.01)
    client.post(
        "/api/audits",
        json={"account_id": b, "role_arn": f"arn:aws:iam::{b}:role/Y"},
    )
    body = client.get("/api/accounts").json()
    assert [r["account_id"] for r in body] == [b, a]
    assert all("role_arn" in r and "last_audit_at" in r for r in body)
    # List view does NOT include created_at (kept lean).
    assert all("created_at" not in r for r in body)


# ---- POST /api/audits/rerun -------------------------------------------------


def test_rerun_returns_404_when_account_unknown(client):
    resp = client.post(
        "/api/audits/rerun", json={"account_id": ACCOUNT, "region": "us-east-1"}
    )
    assert resp.status_code == 404
    assert "No saved role" in resp.json()["error"]


def test_rerun_uses_saved_role_arn_and_creates_audit(client, db):
    # First, populate the account memory via a normal audit.
    first = client.post(
        "/api/audits",
        json={"account_id": ACCOUNT, "role_arn": ROLE_ARN, "region": "us-east-1"},
    )
    assert first.status_code == 202

    # Now re-run by account_id only.
    resp = client.post(
        "/api/audits/rerun",
        json={"account_id": ACCOUNT, "region": "us-east-1"},
    )
    assert resp.status_code == 202
    new_id = resp.json()["audit_run_id"]
    assert new_id and new_id != first.json()["audit_run_id"]

    # The new audit document carries the saved role_arn.
    new_run = db["audit_runs"].find_one({"_id": new_id})
    assert new_run["role_arn"] == ROLE_ARN
    assert new_run["account_id"] == ACCOUNT


def test_rerun_rejects_invalid_account_id(client):
    resp = client.post(
        "/api/audits/rerun", json={"account_id": "abcdefghijkl"}
    )
    assert resp.status_code == 400


# ---- route registration -----------------------------------------------------


def test_phase4_5_routes_are_registered():
    paths = {r.path for r in main.app.routes}
    expected = {
        "/api/accounts",
        "/api/accounts/{account_id}",
        "/api/audits/rerun",
    }
    missing = expected - paths
    assert not missing, f"Missing Phase 4.5 routes: {missing}"
