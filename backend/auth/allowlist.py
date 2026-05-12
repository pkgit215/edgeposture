"""Invite allowlist for Phase 1 closed beta.

Source: `INVITE_ALLOWLIST` env var, comma-separated. Supports:
  * exact emails:      `pkennedyvt@gmail.com`
  * domain wildcards:  `*@yourcompany.com`

Default (unset / empty) = closed (no one allowed in). The maintainer
MUST populate this env var to let anyone past the Google callback.
"""
from __future__ import annotations

import os
from typing import Iterable


def _parse(raw: str) -> list[str]:
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def is_allowed(email: str, *, raw_list: str | None = None) -> bool:
    """True iff `email` matches any rule in `INVITE_ALLOWLIST`.

    `raw_list` override is for tests; in normal use the env var is read
    fresh each call so the maintainer can rotate without a restart.
    """
    e = (email or "").strip().lower()
    if not e:
        return False
    src = raw_list if raw_list is not None else os.environ.get(
        "INVITE_ALLOWLIST", ""
    )
    entries = _parse(src)
    if not entries:
        return False
    for entry in entries:
        if entry.startswith("*@"):
            if e.endswith(entry[1:]):  # "*@foo.com" → endswith "@foo.com"
                return True
        elif entry == e:
            return True
    return False


def current_entries() -> Iterable[str]:
    """Debug helper — returns the currently-loaded allowlist."""
    return _parse(os.environ.get("INVITE_ALLOWLIST", ""))
