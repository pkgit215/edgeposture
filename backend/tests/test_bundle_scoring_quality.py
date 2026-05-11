"""Bundle 1 — Issue #4 (signature-class correlation) + Issue #5 (URL decode)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)

import mongomock
import pytest

from services import audit as audit_mod
from services import aws_waf
from services import db as db_mod
from services.signature_class import (
    classify_request_pattern,
    classify_rule_intent,
)


# --- Issue #4 — signature_class lookups -----------------------------------


def test_signature_class_classify_rule_intent_basic():
    assert classify_rule_intent({}, "BlockShellshockUA") == "shellshock"
    assert classify_rule_intent({}, "WPBlockAdminPath") == "admin_path"
    assert classify_rule_intent({}, "BlockOldCurlScanners") == "curl_ua"
    assert classify_rule_intent({}, "BlockRateLimit500") == "rate_limit"
    # Statement-only path (name carries no signal).
    sqli_stmt = {
        "ByteMatchStatement": {"SearchString": "' or '1'='1"}
    }
    assert classify_rule_intent(sqli_stmt, "Generic") == "sqli"
    xss_stmt = {
        "ByteMatchStatement": {"SearchString": "<script"}
    }
    assert classify_rule_intent(xss_stmt, "Generic") == "xss"


def test_signature_class_classify_rule_intent_unknown():
    # No keyword in the name, no telltale in the statement.
    assert classify_rule_intent({}, "GenericPolicy") is None
    assert classify_rule_intent(
        {"ByteMatchStatement": {"SearchString": "/healthz"}},
        "HealthAllow",
    ) is None


def test_signature_class_classify_request_pattern_decodes_xss():
    raw = "/<script>alert(1)</script>"
    enc = "/%3Cscript%3Ealert(1)%3C/script%3E"
    classes_raw = classify_request_pattern(uri=raw)
    classes_enc = classify_request_pattern(uri=enc)
    assert classes_raw == classes_enc == {"xss"}


def test_signature_class_classify_request_pattern_shellshock_in_headers():
    headers = [{"name": "user-agent", "value": "() { :; }; /bin/cat /etc/passwd"}]
    classes = classify_request_pattern(headers=headers,
                                       ua="() { :; }; /bin/cat /etc/passwd")
    # Header carries both shellshock token AND /etc/passwd (unix_cve).
    assert "shellshock" in classes
    assert "unix_cve" in classes


# --- Issue #5 — URL-decoded scoring ---------------------------------------


def _req(uri="", args="", headers=None):
    return {"action": "ALLOW", "httpRequest": {
        "uri": uri, "args": args, "headers": headers or [],
    }}


def test_score_request_suspicion_decodes_url_encoded_xss():
    enc = aws_waf.score_request_suspicion(
        _req(uri="/%3Cscript%3Ealert(1)%3C/script%3E"),
    )
    raw = aws_waf.score_request_suspicion(
        _req(uri="/<script>alert(1)</script>"),
    )
    assert enc == raw
    assert enc >= 6  # _S_XSS


def test_score_request_suspicion_preserves_original_uri_in_sample(monkeypatch):
    """The persisted sample retains the encoded URI as it arrived from
    AWS — only pattern matching uses the decoded form."""
    req = _req(uri="/%3Cscript%3E")
    score = aws_waf.score_request_suspicion(req)
    assert score >= 6
    # `score_request_suspicion` must NOT mutate the input.
    assert req["httpRequest"]["uri"] == "/%3Cscript%3E"


def test_score_request_suspicion_does_not_double_decode():
    """`%2525` is `%25` after one decode, NOT `%`. We score on the
    once-decoded form so legitimate `%25` literals are preserved."""
    from urllib.parse import unquote_plus
    assert unquote_plus("/%2525") == "/%25"
    # Smoke — neither form scores XSS (no `<script` after one decode).
    assert aws_waf.score_request_suspicion(_req(uri="/%2525")) == 0


# --- Integration — dead_rule escalation rubric ----------------------------


def _make_dead_rule(rule_name, statement_json=None):
    return {
        "rule_name": rule_name, "web_acl_name": "acl-x",
        "priority": 5, "action": "BLOCK", "rule_kind": "custom",
        "statement_json": statement_json or {}, "hit_count": 0,
        "count_mode_hits": 0, "last_fired": None, "sample_uris": [],
        "fms_managed": False, "override_action": None,
        "managed_rule_overrides": [],
    }


def _run(monkeypatch, *, rule, suspicious, label):
    db = mongomock.MongoClient()[f"ruleiq_bundle_{label}"]
    db_mod.set_test_db(db)

    def fake_load(*_a, **_kw):
        return [rule], {
            "data_source": "fixture", "fms_visibility": None,
            "logging_available": True, "web_acl_count": 1,
            "web_acls": [{"name": "acl-x", "scope": "REGIONAL", "arn": None,
                          "attached_resources": ["demo://x"], "attached": True}],
            "orphan_acl_names": set(),
            "suspicious_requests": suspicious,
        }
    monkeypatch.setattr(audit_mod, "_load_rules_from_fixtures", fake_load)
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline",
        lambda rules, **_kw: {
            "rules": [{**r, "ai_explanation": {"explanation": "m",
                       "working": True, "concerns": None}} for r in rules],
            "findings": [{
                "type": "dead_rule", "severity": "high",
                "title": f"{rule['rule_name']} Not Firing",
                "description": "x", "recommendation": "y",
                "affected_rules": [rule["rule_name"]], "confidence": 0.7,
            }],
        })
    audit_id = audit_mod.create_audit_run(
        db=db, account_id="123456789012", role_arn=None,
        region="us-east-1", log_window_days=30, external_id=None,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    return next(
        f for f in db["findings"].find({"audit_run_id": audit_id})
        if f["type"] == "dead_rule"
    )


def test_dead_rule_escalates_to_high_when_class_matches_observed(monkeypatch):
    """Bundle 1 — `BlockShellshock` + shellshock in suspicious → HIGH,
    with `evidence='signature_class_match'` and `signature_class='shellshock'`."""
    suspicious = [{
        "httpRequest": {"uri": "/", "args": "",
                        "headers": [{"name": "user-agent",
                                     "value": "() { :; }; /bin/cat"}]},
        "_signature_classes": ["shellshock"],
    }]
    dead = _run(monkeypatch,
                rule=_make_dead_rule("BlockShellshockUA"),
                suspicious=suspicious, label="esc")
    assert dead["severity"] == "high"
    assert dead["evidence"] == "signature_class_match"
    assert dead["signature_class"] == "shellshock"


def test_dead_rule_stays_medium_when_class_does_not_match_observed(monkeypatch):
    """Bundle 1 — LegacyDeadRule (intent=None) + shellshock observed →
    MEDIUM. No false-positive escalation across unrelated classes."""
    suspicious = [{
        "httpRequest": {"uri": "/", "args": "",
                        "headers": [{"name": "user-agent",
                                     "value": "() { :; };"}]},
        "_signature_classes": ["shellshock"],
    }]
    dead = _run(monkeypatch,
                rule=_make_dead_rule("LegacyDeadRule"),
                suspicious=suspicious, label="nomatch")
    assert dead["severity"] == "medium"
    assert dead.get("signature_class") is None


def test_dead_rule_stays_medium_when_no_suspicious_sample(monkeypatch):
    """Bundle 1 — even a shellshock-named dead rule stays MEDIUM if no
    attack-shaped traffic was observed in the audit window."""
    dead = _run(monkeypatch,
                rule=_make_dead_rule("BlockShellshockUA"),
                suspicious=[], label="empty")
    assert dead["severity"] == "medium"
