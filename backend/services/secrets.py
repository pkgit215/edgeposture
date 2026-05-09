"""Secrets loader for RuleIQ Phase 0.

Resolution order (per secret):
    1. Environment variable
    2. AWS Secrets Manager (boto3 default credential chain)

Values are cached in module-level singletons after the first successful fetch.
"""
from __future__ import annotations

import json
import os
from typing import Optional

import boto3

_OPENAI_KEY_CACHE: Optional[str] = None
_MONGO_URI_CACHE: Optional[str] = None

OPENAI_SECRET_ID = "ruleiq/openai"
MONGO_SECRET_ID = "ruleiq/mongodb"
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

    Phase 0 stub — function is implemented but no Mongo client is instantiated
    anywhere in the app. Reserved for Phase 1.
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


def _reset_cache_for_tests() -> None:
    """Test-only helper to clear cached singletons."""
    global _OPENAI_KEY_CACHE, _MONGO_URI_CACHE
    _OPENAI_KEY_CACHE = None
    _MONGO_URI_CACHE = None
