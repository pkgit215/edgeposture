"""Phase 1 of #45 — Google OAuth + tenants collection.

Mocks the Google token exchange + ID token verification so the tests
don't need network access or real Google JWKS. The real production code
path is exercised end-to-end *except* for those two boundary calls.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# We want REAL middleware enforcement in these tests.
os.environ.pop("EDGEPOSTURE_TESTING", None)
# Session-signing secret — bypasses Secrets Manager for the test run.
os.environ.setdefault("EDGEPOSTURE_SESSION_SECRET", "x" * 64)
# Google client_id for ID-token aud claim verification.
os.environ.setdefault(
    "EDGEPOSTURE_GOOGLE_OAUTH",
    '{"client_id":"test-client.apps.googleusercontent.com",'
    '"client_secret":"test-client-secret"}',
)

import mongomock
import pytest
from fastapi.testclient import TestClient

# Import after env vars are set.
from auth import google as google_mod
from auth import sessions as sessions_mod
from services import db as db_mod
import main as main_mod  # FastAPI app


@pytest.fixture
def client(monkeypatch):
    """Fresh mongomock DB + TestClient per test."""
    db = mongomock.MongoClient()["edgeposture_auth_phase1"]
    db_mod.set_test_db(db)
    monkeypatch.setenv("INVITE_ALLOWLIST", "pkennedyvt@gmail.com,*@allowed.io")
    # Skip the startup seed hook entirely.
    monkeypatch.setenv("EDGEPOSTURE_TESTING", "0")
    with TestClient(main_mod.app, follow_redirects=False) as c:
        yield c
    db_mod.clear_test_db()


def _mock_google_exchange(
    monkeypatch, *, email: str, sub: str, name: str = "Test User",
):
    """Replace the two network boundary calls with deterministic fakes."""
    monkeypatch.setattr(
        google_mod, "_exchange_code_for_tokens",
        lambda code, redirect_uri: {"id_token": "fake.jwt.token"},
    )
    monkeypatch.setattr(
        google_mod, "_verify_id_token",
        lambda id_token_str, client_id: {
            "iss": "accounts.google.com",
            "sub": sub,
            "email": email,
            "email_verified": True,
            "name": name,
        },
    )


# =========================================================================
# Phase 1 acceptance criteria
# =========================================================================


def test_google_oauth_callback_happy_path(client, monkeypatch):
    """Allowlisted email → tenant created, session cookie set, redirect
    to `/app`."""
    _mock_google_exchange(
        monkeypatch, email="pkennedyvt@gmail.com", sub="google-sub-001",
        name="Pat Kennedy",
    )
    state = sessions_mod.sign_state({"nonce": "test"})
    resp = client.get(
        "/auth/google/callback", params={"code": "fake-code", "state": state},
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/app"
    assert sessions_mod.COOKIE_NAME in resp.cookies
    # Tenant row exists.
    db = db_mod.get_db()
    tenant = db["tenants"].find_one({"email": "pkennedyvt@gmail.com"})
    assert tenant is not None
    assert tenant["google_sub"] == "google-sub-001"
    assert tenant["name"] == "Pat Kennedy"
    assert tenant["status"] == "active"
    assert tenant.get("external_id")  # Phase 3 placeholder, must exist.


def test_callback_email_not_on_allowlist(client, monkeypatch):
    """Non-allowlisted email → 403 page, NO tenant row created."""
    _mock_google_exchange(
        monkeypatch, email="random@stranger.com", sub="google-sub-stranger",
    )
    state = sessions_mod.sign_state({"nonce": "test"})
    resp = client.get(
        "/auth/google/callback", params={"code": "fake-code", "state": state},
    )
    assert resp.status_code == 403
    assert "Beta access required" in resp.text
    assert "random@stranger.com" in resp.text
    db = db_mod.get_db()
    assert db["tenants"].count_documents({}) == 0


def test_existing_tenant_loaded_on_repeat_signin(client, monkeypatch):
    """Second sign-in by same Google sub → no duplicate tenant, but
    `last_seen_at` is updated."""
    _mock_google_exchange(
        monkeypatch, email="user@allowed.io", sub="google-sub-002",
    )
    state = sessions_mod.sign_state({"nonce": "a"})
    r1 = client.get(
        "/auth/google/callback", params={"code": "c1", "state": state},
    )
    assert r1.status_code == 302
    db = db_mod.get_db()
    first = db["tenants"].find_one({"google_sub": "google-sub-002"})
    assert first is not None
    first_seen = first["last_seen_at"]

    # Second sign-in. New state token so verify_state passes again.
    state2 = sessions_mod.sign_state({"nonce": "b"})
    r2 = client.get(
        "/auth/google/callback", params={"code": "c2", "state": state2},
    )
    assert r2.status_code == 302
    assert db["tenants"].count_documents({"google_sub": "google-sub-002"}) == 1
    second = db["tenants"].find_one({"google_sub": "google-sub-002"})
    assert second["last_seen_at"] >= first_seen


def test_api_me_requires_session(client, monkeypatch):
    """No cookie → 401. Valid cookie → 200 with tenant info."""
    r_anon = client.get("/api/me")
    assert r_anon.status_code == 401
    assert r_anon.json() == {"error": "authentication_required"}

    # Sign in to get a real session.
    _mock_google_exchange(
        monkeypatch, email="pkennedyvt@gmail.com", sub="me-sub",
        name="Me Test",
    )
    state = sessions_mod.sign_state({"nonce": "me"})
    cb = client.get(
        "/auth/google/callback", params={"code": "c", "state": state},
    )
    assert cb.status_code == 302
    cookie_value = cb.cookies.get(sessions_mod.COOKIE_NAME)
    assert cookie_value

    r = client.get(
        "/api/me", cookies={sessions_mod.COOKIE_NAME: cookie_value},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "pkennedyvt@gmail.com"
    assert body["name"] == "Me Test"
    assert body.get("tenant_id")


def test_demo_routes_remain_anonymous(client):
    """`/api/demo/audit` must stay public — it's the top-of-funnel.
    No cookie, 200 expected."""
    r = client.get("/api/demo/audit")
    assert r.status_code == 200, (
        "demo audit must remain anonymous public access — top-of-funnel"
    )
    # Sanity: must NOT contain the auth_required error body.
    assert r.json().get("error") != "authentication_required"


def test_dist_route_remains_anonymous(client):
    """`/api/dist/*` serves the deploy-artifact tarballs that Cloud9
    pulls to apply branches. Must remain public — anonymous curl from
    outside any session is the whole point of the apply pipeline.

    Pins the regression we hit when the Phase 1 auth middleware first
    landed and started 401ing the apply URL.
    """
    # We don't have a real artifact in the test client (no static
    # mount), so the route returns 404 — but critically, NOT 401.
    # The middleware MUST let the request through to the route layer.
    r = client.get("/api/dist/some-tarball-that-doesnt-exist.tar.gz")
    assert r.status_code != 401, (
        "/api/dist/* must NOT be auth-gated — Cloud9 apply pipeline "
        "pulls these tarballs anonymously. Add it to "
        "auth.middleware._PUBLIC_PREFIXES."
    )
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    assert body.get("error") != "authentication_required"


def test_audits_route_now_requires_auth(client):
    """`/api/audits` (and any non-exempt /api/ route) now 401s for
    anonymous clients."""
    r = client.get("/api/audits")
    assert r.status_code == 401
    assert r.json() == {"error": "authentication_required"}
    # `/api/health` stays public (App Runner health probe).
    assert client.get("/api/health").status_code == 200


# Bonus invariants the brief implies but doesn't enumerate.


def test_logout_clears_session(client, monkeypatch):
    _mock_google_exchange(
        monkeypatch, email="pkennedyvt@gmail.com", sub="logout-sub",
    )
    state = sessions_mod.sign_state({"nonce": "lo"})
    cb = client.get(
        "/auth/google/callback", params={"code": "c", "state": state},
    )
    cookie_value = cb.cookies.get(sessions_mod.COOKIE_NAME)
    client.cookies.set(sessions_mod.COOKIE_NAME, cookie_value)
    r = client.post("/auth/logout")
    assert r.status_code == 200
    # Session row should be gone — re-using the now-clear cookie 401s.
    r2 = client.get(
        "/api/me", cookies={sessions_mod.COOKIE_NAME: cookie_value},
    )
    assert r2.status_code == 401


def test_invalid_state_rejected(client, monkeypatch):
    _mock_google_exchange(
        monkeypatch, email="pkennedyvt@gmail.com", sub="csrf-sub",
    )
    r = client.get(
        "/auth/google/callback",
        params={"code": "c", "state": "tampered.not.signed"},
    )
    assert r.status_code == 400
    assert "invalid_state" in r.text
