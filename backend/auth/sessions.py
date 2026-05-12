"""Session creation / lookup / deletion, plus signed-cookie helpers.

The cookie carries ONLY the session_id (a uuid4); the tenant_id is
resolved server-side by reading the `sessions` collection. This is the
opposite of a JWT-in-localStorage pattern — we want the cookie to be
cheap to revoke (just delete the row in Mongo) and we don't want to
expose tenant identifiers to the browser.

Cookie attributes:
  * HttpOnly, SameSite=Lax
  * Secure when EDGEPOSTURE_ENV=production (i.e. behind App Runner HTTPS)
  * Max-Age = SESSION_TTL_DAYS (default 30)
  * Signature: itsdangerous URLSafeTimedSerializer keyed on the
    session-secret from AWS Secrets Manager
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from services import db as db_mod
from services import secrets as secrets_mod

COOKIE_NAME = "edgeposture_session"
SESSION_TTL_DAYS = 30
_STATE_TTL_SECONDS = 600  # 10 min — for the OAuth `state` round-trip
_SERIALIZER_SALT = "edgeposture.session.v1"
_STATE_SALT = "edgeposture.oauth.state.v1"


def _serializer(salt: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        secret_key=secrets_mod.get_session_secret(),
        salt=salt,
    )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def is_production() -> bool:
    return os.environ.get("EDGEPOSTURE_ENV", "").lower() == "production"


# ---------- OAuth `state` round-trip ---------------------------------------


def sign_state(payload: dict) -> str:
    """Pack the OAuth state into a signed, time-limited token. The
    callback decodes + validates this to prove the request originated
    here (CSRF defence)."""
    return _serializer(_STATE_SALT).dumps(payload)


def verify_state(token: str) -> Optional[dict]:
    """Return the decoded state payload, or None if the signature is
    bad / the token is older than 10 minutes."""
    try:
        return _serializer(_STATE_SALT).loads(
            token, max_age=_STATE_TTL_SECONDS,
        )
    except (BadSignature, SignatureExpired):
        return None


# ---------- Session cookie -------------------------------------------------


def sign_session_id(session_id: str) -> str:
    return _serializer(_SERIALIZER_SALT).dumps(session_id)


def verify_session_id(signed: str) -> Optional[str]:
    """Return the raw session_id, or None if the cookie was tampered
    with or older than SESSION_TTL_DAYS."""
    try:
        return _serializer(_SERIALIZER_SALT).loads(
            signed, max_age=SESSION_TTL_DAYS * 24 * 3600,
        )
    except (BadSignature, SignatureExpired):
        return None


def cookie_kwargs() -> dict:
    """Set-cookie kwargs that match FastAPI's Response.set_cookie API."""
    return {
        "key": COOKIE_NAME,
        "max_age": SESSION_TTL_DAYS * 24 * 3600,
        "path": "/",
        "httponly": True,
        "secure": is_production(),
        "samesite": "lax",
    }


# ---------- Session record (MongoDB) ---------------------------------------


def create_session(tenant_id: str) -> str:
    """Insert a new session row, return the raw session_id (caller is
    responsible for signing it before putting it in the cookie)."""
    db = db_mod.get_db()
    sid = str(uuid.uuid4())
    now = _utcnow()
    db["sessions"].insert_one({
        "_id": sid,
        "tenant_id": tenant_id,
        "created_at": now,
        "last_seen_at": now,
        "expires_at": now + timedelta(days=SESSION_TTL_DAYS),
    })
    return sid


def lookup_session(session_id: str) -> Optional[dict]:
    """Fetch the session row and bump `last_seen_at`. Returns None if
    the session is missing or expired."""
    db = db_mod.get_db()
    doc = db["sessions"].find_one({"_id": session_id})
    if not doc:
        return None
    expires_at = doc.get("expires_at")
    if expires_at is not None:
        # Mongo strips tzinfo on insert — re-attach UTC for comparison.
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < _utcnow():
            db["sessions"].delete_one({"_id": session_id})
            return None
    db["sessions"].update_one(
        {"_id": session_id}, {"$set": {"last_seen_at": _utcnow()}},
    )
    return doc


def delete_session(session_id: str) -> None:
    db = db_mod.get_db()
    db["sessions"].delete_one({"_id": session_id})


def lookup_tenant_by_session_cookie(signed_cookie: str) -> Optional[dict]:
    """Convenience: signed cookie → tenant doc. Returns None on any
    failure (bad signature, missing session, missing tenant, expired)."""
    sid = verify_session_id(signed_cookie)
    if not sid:
        return None
    session = lookup_session(sid)
    if not session:
        return None
    db = db_mod.get_db()
    tenant = db["tenants"].find_one({"tenant_id": session["tenant_id"]})
    return tenant
