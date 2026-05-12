"""MongoDB client singleton and index management for RuleIQ Phase 1.

Driver choice: pymongo (sync). FastAPI BackgroundTasks already run in a
worker thread and the audit worker mixes blocking OpenAI calls with CPU
work; async adds complexity without buying anything.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.database import Database
from pymongo.errors import PyMongoError

from .secrets import get_mongo_uri

logger = logging.getLogger(__name__)

DB_NAME = os.environ.get("MONGO_DB_NAME", "ruleiq")
SERVER_SELECTION_TIMEOUT_MS = 5000

_client: Optional[MongoClient] = None
_db: Optional[Database] = None
_indexes_ensured = False
_test_db_override: Optional[Any] = None  # set by tests via set_test_db


def set_test_db(db: Any) -> None:
    """Inject a test double (e.g. mongomock) for the duration of a test."""
    global _test_db_override, _indexes_ensured
    _test_db_override = db
    _indexes_ensured = False


def clear_test_db() -> None:
    global _test_db_override, _indexes_ensured
    _test_db_override = None
    _indexes_ensured = False


def get_db() -> Database:
    """Return the live database, lazily connecting on first use.

    Connection failures bubble up as PyMongoError so callers can decide
    whether to surface them or degrade gracefully.
    """
    global _client, _db
    if _test_db_override is not None:
        ensure_indexes(_test_db_override)
        return _test_db_override

    if _db is not None:
        return _db

    uri = get_mongo_uri()
    logger.info("Connecting to MongoDB (db=%s)", DB_NAME)
    _client = MongoClient(
        uri,
        serverSelectionTimeoutMS=SERVER_SELECTION_TIMEOUT_MS,
        appname="ruleiq-phase1",
    )
    # Force server-selection now so we fail fast with a clear log line.
    _client.admin.command("ping")
    _db = _client[DB_NAME]
    ensure_indexes(_db)
    return _db


def ping() -> bool:
    """Cheap health probe — never raises, returns True/False."""
    try:
        db = get_db()
        # mongomock has no admin command, fall back to a list_collection_names
        if hasattr(db, "client") and db.client is not None:
            try:
                db.client.admin.command("ping")
                return True
            except PyMongoError:
                return False
        # Override path (mongomock): treat reachable.
        db.list_collection_names()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("MongoDB ping failed: %s", exc)
        return False


def ensure_indexes(db: Database) -> None:
    """Idempotently create the indexes Phase 1 relies on."""
    global _indexes_ensured
    if _indexes_ensured:
        return
    try:
        db["accounts"].create_index(
            [("account_id", ASCENDING)], unique=True, name="account_id_unique"
        )
        db["audit_runs"].create_index(
            [("account_id", ASCENDING)], name="audit_runs_account_id"
        )
        db["audit_runs"].create_index(
            [("created_at", DESCENDING)], name="audit_runs_created_at_desc"
        )
        db["audit_runs"].create_index(
            [("seed", ASCENDING)], name="audit_runs_seed"
        )
        db["rules"].create_index(
            [("audit_run_id", ASCENDING)], name="rules_audit_run_id"
        )
        db["findings"].create_index(
            [("audit_run_id", ASCENDING)], name="findings_audit_run_id"
        )
        # Phase 1 of #45 — tenants + sessions.
        db["tenants"].create_index(
            [("tenant_id", ASCENDING)], unique=True, name="tenants_tenant_id_unique"
        )
        db["tenants"].create_index(
            [("email", ASCENDING)], unique=True, name="tenants_email_unique"
        )
        db["tenants"].create_index(
            [("google_sub", ASCENDING)], name="tenants_google_sub"
        )
        # TTL — Mongo evicts session rows once `expires_at` is in the
        # past (expireAfterSeconds=0 means "immediately at the time
        # stored in this field"). Cookie max-age and session row
        # expiry are aligned at SESSION_TTL_DAYS.
        db["sessions"].create_index(
            [("expires_at", ASCENDING)], name="sessions_ttl",
            expireAfterSeconds=0,
        )
        _indexes_ensured = True
    except Exception as exc:  # noqa: BLE001
        # Don't crash startup over an index race.
        logger.warning("ensure_indexes encountered: %s", exc)
