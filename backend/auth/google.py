"""Google OAuth Authorization Code flow — server-side.

Routes:
  GET  /auth/google/login     redirect to Google with signed `state`
  GET  /auth/google/callback  exchange code, verify ID token, create tenant
                              (if allowlisted), set session cookie, redirect
  POST /auth/logout           delete session row + clear cookie
  GET  /api/me                read session, return {tenant_id, email, name}

ID token verification uses `google.oauth2.id_token.verify_oauth2_token`
which validates signature against Google's JWKS, exp, iat, and aud.
We additionally check the `iss` claim.

OIDC discovery doc is fetched once at module import and cached. Falls
back to hard-coded endpoints if the discovery URL is unreachable so the
service still boots in air-gapped/test envs.
"""
from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from auth import allowlist, sessions
from services import db as db_mod
from services import secrets as secrets_mod

logger = logging.getLogger(__name__)
router = APIRouter()

_OIDC_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
# Hard-coded fallback endpoints — Google has been stable on these for years.
_OIDC_FALLBACK = {
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
    "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
}
_oidc_cache: Optional[Dict[str, Any]] = None


def _get_oidc_config() -> Dict[str, Any]:
    """Fetch + cache the discovery doc. Never raises — falls back to
    the hard-coded endpoints if the network is unreachable."""
    global _oidc_cache
    if _oidc_cache is not None:
        return _oidc_cache
    try:
        with httpx.Client(timeout=5.0) as c:
            r = c.get(_OIDC_DISCOVERY_URL)
            r.raise_for_status()
            _oidc_cache = r.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "OIDC discovery fetch failed (%s) — falling back to "
            "hard-coded Google endpoints.", exc,
        )
        _oidc_cache = dict(_OIDC_FALLBACK)
    return _oidc_cache


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _absolute_redirect_uri(request: Request) -> str:
    """The redirect_uri we registered with Google. Honors a
    `GOOGLE_OAUTH_REDIRECT_URI` env override (set in App Runner config
    so prod always uses `https://edgeposture.io/auth/google/callback`
    regardless of what FastAPI thinks its hostname is behind the LB)."""
    env_override = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI")
    if env_override:
        return env_override
    # Default: derive from the inbound request. Works for `localhost:8000`
    # in dev and any host in tests.
    return str(request.url_for("google_oauth_callback"))


def _login_url(request: Request) -> str:
    creds = secrets_mod.get_google_oauth_credentials()
    state = sessions.sign_state({"nonce": uuid.uuid4().hex})
    params = {
        "client_id": creds["client_id"],
        "redirect_uri": _absolute_redirect_uri(request),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    auth_ep = _get_oidc_config()["authorization_endpoint"]
    return f"{auth_ep}?{urlencode(params)}"


# ---------- ID token verification (mockable) -------------------------------


def _verify_id_token(id_token_str: str, client_id: str) -> Dict[str, Any]:
    """Wrapper around `google.oauth2.id_token.verify_oauth2_token` —
    isolated as a module-level function so tests can monkeypatch it
    without needing real Google JWKS access."""
    # Lazy import — keeps test envs that don't install google-auth working.
    from google.auth.transport import requests as google_requests  # noqa: PLC0415
    from google.oauth2 import id_token as google_id_token  # noqa: PLC0415
    info = google_id_token.verify_oauth2_token(
        id_token_str, google_requests.Request(), client_id,
    )
    iss = info.get("iss")
    if iss not in ("accounts.google.com", "https://accounts.google.com"):
        raise ValueError(f"Invalid ID token issuer: {iss!r}")
    return info


def _exchange_code_for_tokens(
    code: str, redirect_uri: str,
) -> Dict[str, Any]:
    """POST to the token endpoint with the auth code. Mockable as
    `auth.google._exchange_code_for_tokens`."""
    creds = secrets_mod.get_google_oauth_credentials()
    token_ep = _get_oidc_config()["token_endpoint"]
    with httpx.Client(timeout=10.0) as c:
        r = c.post(
            token_ep,
            data={
                "code": code,
                "client_id": creds["client_id"],
                "client_secret": creds["client_secret"],
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        r.raise_for_status()
        return r.json()


# ---------- Tenant upsert --------------------------------------------------


def _upsert_tenant_from_google(info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Look up by `google_sub`; create on first sign-in iff email is on
    the allowlist. Returns the tenant doc, or None if denied."""
    google_sub = info.get("sub")
    email = (info.get("email") or "").strip().lower()
    name = info.get("name") or email
    if not google_sub or not email:
        return None
    db = db_mod.get_db()
    existing = db["tenants"].find_one({"google_sub": google_sub})
    if existing:
        db["tenants"].update_one(
            {"google_sub": google_sub},
            {"$set": {"last_seen_at": _utcnow(), "name": name}},
        )
        return db["tenants"].find_one({"google_sub": google_sub})
    if not allowlist.is_allowed(email):
        logger.info(
            "Google sign-in denied — email %r not on INVITE_ALLOWLIST.",
            email,
        )
        return None
    tenant_id = str(uuid.uuid4())
    doc = {
        "tenant_id": tenant_id,
        "email": email,
        "name": name,
        "google_sub": google_sub,
        # Phase 3 placeholder — real per-tenant ExternalId derivation
        # ships in #45 item 1.
        "external_id": str(uuid.uuid4()),
        "created_at": _utcnow(),
        "last_seen_at": _utcnow(),
        "status": "active",
    }
    db["tenants"].insert_one(doc)
    return doc


# ---------- Routes ---------------------------------------------------------


@router.get("/auth/google/login")
def google_oauth_login(request: Request) -> RedirectResponse:
    return RedirectResponse(_login_url(request), status_code=302)


_DENIED_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Beta access required — EdgePosture</title>
<style>body{{font-family:system-ui,sans-serif;max-width:560px;margin:80px auto;
padding:0 24px;color:#0f172a;line-height:1.5}}h1{{font-size:20px}}a{{color:#1d4ed8}}
.card{{border:1px solid #e2e8f0;border-radius:8px;padding:24px;background:#fff}}
.muted{{color:#64748b;font-size:14px}}</style></head>
<body><div class="card" data-testid="beta-denied">
<h1>Beta access required</h1>
<p>EdgePosture is in closed beta. Your Google account
<strong>{email}</strong> is not on the invite list yet.</p>
<p>Email <a href="mailto:hello@edgeposture.io">hello@edgeposture.io</a>
for access.</p>
<p class="muted"><a href="/demo">Try the demo →</a></p>
</div></body></html>"""


@router.get("/auth/google/callback", name="google_oauth_callback")
def google_oauth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
) -> Response:
    if error:
        raise HTTPException(status_code=400, detail=f"google_error: {error}")
    if not code or not state:
        raise HTTPException(status_code=400, detail="missing code or state")
    if sessions.verify_state(state) is None:
        raise HTTPException(status_code=400, detail="invalid_state")
    try:
        tokens = _exchange_code_for_tokens(
            code, _absolute_redirect_uri(request),
        )
    except httpx.HTTPError as exc:
        logger.error("Token exchange failed: %s", exc)
        raise HTTPException(status_code=400, detail="token_exchange_failed")
    id_token_str = tokens.get("id_token")
    if not id_token_str:
        raise HTTPException(status_code=400, detail="no_id_token")
    creds = secrets_mod.get_google_oauth_credentials()
    try:
        info = _verify_id_token(id_token_str, creds["client_id"])
    except Exception as exc:  # noqa: BLE001
        logger.error("ID token verification failed: %s", exc)
        raise HTTPException(status_code=400, detail="invalid_id_token")

    tenant = _upsert_tenant_from_google(info)
    if tenant is None:
        return HTMLResponse(
            _DENIED_HTML.format(email=(info.get("email") or "(unknown)")),
            status_code=403,
        )
    sid = sessions.create_session(tenant["tenant_id"])
    resp = RedirectResponse(url="/app", status_code=302)
    resp.set_cookie(value=sessions.sign_session_id(sid),
                    **sessions.cookie_kwargs())
    return resp


@router.post("/auth/logout")
def logout(request: Request) -> JSONResponse:
    cookie = request.cookies.get(sessions.COOKIE_NAME)
    if cookie:
        sid = sessions.verify_session_id(cookie)
        if sid:
            sessions.delete_session(sid)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(key=sessions.COOKIE_NAME, path="/")
    return resp


@router.get("/api/me")
def me(request: Request) -> Dict[str, Any]:
    cookie = request.cookies.get(sessions.COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=401, detail="authentication_required")
    tenant = sessions.lookup_tenant_by_session_cookie(cookie)
    if not tenant:
        raise HTTPException(status_code=401, detail="authentication_required")
    return {
        "tenant_id": tenant["tenant_id"],
        "email": tenant["email"],
        "name": tenant.get("name"),
        "created_at": tenant.get("created_at"),
    }
