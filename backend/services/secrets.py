"""Secrets loader for RuleIQ.

Resolution order (per secret):
    1. Environment variable
    2. AWS Secrets Manager (boto3 default credential chain)
    3. (EXTERNAL_ID_SECRET only) process-level random fallback so the app
       still boots — never crashes on missing config.

Values are cached in module-level singletons after the first successful fetch.
"""
from __future__ import annotations

import json
import logging
import os
import secrets as _stdsecrets
from typing import Optional

import boto3

logger = logging.getLogger(__name__)

_OPENAI_KEY_CACHE: Optional[str] = None
_MONGO_URI_CACHE: Optional[str] = None
_EXTERNAL_ID_SECRET_CACHE: Optional[str] = None
_GOOGLE_OAUTH_CACHE: Optional[dict] = None
_SESSION_SECRET_CACHE: Optional[str] = None

OPENAI_SECRET_ID = "ruleiq/openai"
MONGO_SECRET_ID = "ruleiq/mongodb"
EXTERNAL_ID_SECRET_ID = "ruleiq/external-id-secret"
GOOGLE_OAUTH_SECRET_ID = "edgeposture/google-oauth"
SESSION_SECRET_ID = "edgeposture/session-secret"
AWS_REGION = "us-east-1"


def _sm_client():
    return boto3.client("secretsmanager", region_name=AWS_REGION)


def _fetch_secret_string(secret_id: str) -> str:
    resp = _sm_client().get_secret_value(SecretId=secret_id)
    if "SecretString" not in resp:
        raise RuntimeError(f"Secret {secret_id} has no SecretString")
    return resp["SecretString"]


def get_openai_key() -> str:
    """Return the OpenAI API key.

    Order: OPENAI_API_KEY env var, then AWS Secrets Manager (plain text secret).
    """
    global _OPENAI_KEY_CACHE
    if _OPENAI_KEY_CACHE:
        return _OPENAI_KEY_CACHE

    env_val = os.environ.get("OPENAI_API_KEY")
    if env_val:
        _OPENAI_KEY_CACHE = env_val
        return _OPENAI_KEY_CACHE

    raw = _fetch_secret_string(OPENAI_SECRET_ID).strip()
    _OPENAI_KEY_CACHE = raw
    return _OPENAI_KEY_CACHE


def get_mongo_uri() -> str:
    """Return the MongoDB connection URI.

    Order: MONGODB_URI env var, then AWS Secrets Manager (JSON `{"uri": "..."}`).
    """
    global _MONGO_URI_CACHE
    if _MONGO_URI_CACHE:
        return _MONGO_URI_CACHE

    env_val = os.environ.get("MONGODB_URI")
    if env_val:
        _MONGO_URI_CACHE = env_val
        return _MONGO_URI_CACHE

    raw = _fetch_secret_string(MONGO_SECRET_ID)
    parsed = json.loads(raw)
    uri = parsed.get("uri")
    if not uri:
        raise RuntimeError(f"Secret {MONGO_SECRET_ID} JSON missing 'uri' field")
    _MONGO_URI_CACHE = uri
    return _MONGO_URI_CACHE


def get_external_id_secret() -> str:
    """Return the HMAC secret used to derive per-tenant ExternalIds.

    Order:
        1. EXTERNAL_ID_SECRET env var
        2. AWS Secrets Manager (`ruleiq/external-id-secret`, plain text hex)
        3. Process-level random fallback (logged WARNING; the app keeps booting
           but ExternalIds will rotate every restart — visible to the operator
           in the logs).

    Returns the raw secret string. The caller is responsible for encoding it
    to bytes for HMAC.
    """
    global _EXTERNAL_ID_SECRET_CACHE
    if _EXTERNAL_ID_SECRET_CACHE:
        return _EXTERNAL_ID_SECRET_CACHE

    env_val = os.environ.get("EXTERNAL_ID_SECRET")
    if env_val:
        _EXTERNAL_ID_SECRET_CACHE = env_val
        return _EXTERNAL_ID_SECRET_CACHE

    try:
        raw = _fetch_secret_string(EXTERNAL_ID_SECRET_ID).strip()
        if raw:
            _EXTERNAL_ID_SECRET_CACHE = raw
            return _EXTERNAL_ID_SECRET_CACHE
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "EXTERNAL_ID_SECRET unreachable via env or Secrets Manager (%s) — "
            "falling back to a process-level random constant. ExternalIds "
            "will rotate every restart. Bootstrap the secret to fix.",
            exc,
        )

    # Process-level fallback: 64 hex chars (32 bytes). Derived ExternalIds
    # remain stable for the lifetime of THIS process.
    fallback = _stdsecrets.token_hex(32)
    _EXTERNAL_ID_SECRET_CACHE = fallback
    return _EXTERNAL_ID_SECRET_CACHE


def get_google_oauth_credentials() -> dict:
    """Return Google OAuth client_id/client_secret as a dict.

    Order:
      1. EDGEPOSTURE_GOOGLE_OAUTH env var (JSON-encoded)
      2. AWS Secrets Manager: edgeposture/google-oauth (JSON-shaped)
    """
    global _GOOGLE_OAUTH_CACHE
    if _GOOGLE_OAUTH_CACHE:
        return _GOOGLE_OAUTH_CACHE
    env_val = os.environ.get("EDGEPOSTURE_GOOGLE_OAUTH")
    if env_val:
        _GOOGLE_OAUTH_CACHE = json.loads(env_val)
        return _GOOGLE_OAUTH_CACHE
    raw = _fetch_secret_string(GOOGLE_OAUTH_SECRET_ID)
    _GOOGLE_OAUTH_CACHE = json.loads(raw)
    return _GOOGLE_OAUTH_CACHE


def get_session_secret() -> str:
    """Return the secret used to sign session cookies + OAuth state.

    Order:
      1. EDGEPOSTURE_SESSION_SECRET env var (plain text)
      2. AWS Secrets Manager: edgeposture/session-secret (plain text)
    """
    global _SESSION_SECRET_CACHE
    if _SESSION_SECRET_CACHE:
        return _SESSION_SECRET_CACHE
    env_val = os.environ.get("EDGEPOSTURE_SESSION_SECRET")
    if env_val:
        _SESSION_SECRET_CACHE = env_val
        return _SESSION_SECRET_CACHE
    raw = _fetch_secret_string(SESSION_SECRET_ID).strip()
    _SESSION_SECRET_CACHE = raw
    return _SESSION_SECRET_CACHE


def _reset_cache_for_tests() -> None:
    """Test-only helper to clear cached singletons."""
    global _OPENAI_KEY_CACHE, _MONGO_URI_CACHE, _EXTERNAL_ID_SECRET_CACHE
    global _GOOGLE_OAUTH_CACHE, _SESSION_SECRET_CACHE
    _OPENAI_KEY_CACHE = None
    _MONGO_URI_CACHE = None
    _EXTERNAL_ID_SECRET_CACHE = None
    _GOOGLE_OAUTH_CACHE = None
    _SESSION_SECRET_CACHE = None
