"""Deterministic per-tenant ExternalId derivation.

The ExternalId we hand out for a customer's IAM trust policy is HMAC-SHA256
of the customer's AWS account ID under a server-held secret. This makes:

- The ExternalId stable forever for a given account_id (as long as the
  secret is stable). Eliminates the X1/X2 race that broke AssumeRole.
- Different accounts get unrelated ExternalIds (no enumeration).
- Tamper-proof — the backend recomputes server-side on every audit POST
  and never trusts a client-supplied value.

Rotation: rotating EXTERNAL_ID_SECRET in Secrets Manager invalidates ALL
existing customer roles (their trust policies bind the OLD ExternalId).
See docs/known_issues.md for the rotation runbook.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re

from .secrets import get_external_id_secret

logger = logging.getLogger(__name__)

ACCOUNT_ID_RE = re.compile(r"^\d{12}$")


def is_valid_account_id(account_id: str) -> bool:
    return bool(account_id) and bool(ACCOUNT_ID_RE.match(account_id))


def compute_external_id(account_id: str) -> str:
    """HMAC-SHA256(secret, account_id), returned as the first 32 hex chars.

    32 hex chars = 128 bits — well above the IAM ExternalId minimum (>2 chars)
    and far above brute-forcable. Same account_id always returns the same
    value as long as the secret is unchanged.
    """
    if not is_valid_account_id(account_id):
        raise ValueError(f"invalid account_id: {account_id!r}")
    secret_bytes = get_external_id_secret().encode("utf-8")
    digest = hmac.new(
        secret_bytes, account_id.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return digest[:32]
