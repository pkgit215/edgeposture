"""Idempotent demo seed.

On startup, ensure exactly one AuditRun with `seed=True` exists for the
demo account. If Mongo is unreachable, log and skip — App Runner's load
balancer probe must keep returning 200 even when persistence is down.
"""
from __future__ import annotations

import logging
from typing import Optional

from pymongo.database import Database

from . import audit as audit_mod
from . import db as db_mod

logger = logging.getLogger(__name__)

DEMO_ACCOUNT_ID = "123456789012"
DEMO_REGION = "us-east-1"
DEMO_LOG_WINDOW_DAYS = 30


def ensure_demo_seed(db: Optional[Database] = None) -> Optional[str]:
    """Run the audit pipeline once for the demo account if no seed exists.

    Returns the audit_run_id that already existed or was just created, or
    None if seeding was skipped (e.g. Mongo unreachable).
    """
    try:
        if db is None:
            db = db_mod.get_db()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Skipping demo seed — Mongo unreachable: %s", exc)
        return None

    existing = db["audit_runs"].find_one(
        {"seed": True, "account_id": DEMO_ACCOUNT_ID},
        {"_id": 1},
    )
    if existing:
        logger.info("Demo seed already present (audit_run_id=%s)", existing["_id"])
        return str(existing["_id"])

    logger.info("Demo seed missing — running pipeline against fixture rules")
    audit_run_id = audit_mod.create_audit_run(
        db=db,
        account_id=DEMO_ACCOUNT_ID,
        role_arn=None,
        region=DEMO_REGION,
        log_window_days=DEMO_LOG_WINDOW_DAYS,
        seed=True,
    )
    audit_mod.run_audit_pipeline(audit_run_id, db)
    logger.info("Demo seed complete (audit_run_id=%s)", audit_run_id)
    return audit_run_id
