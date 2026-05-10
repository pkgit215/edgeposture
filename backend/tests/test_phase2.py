"""Phase 2 tests — AWS WAF integration, hybrid switch, setup-info, scoring extras.

Strategy:
- moto v5 for sts/wafv2/logs (decorators).
- A small fake `logs` client for `get_rule_stats` so we don't depend on
  moto's filterPattern parser.
- mongomock + monkeypatched ai_pipeline (same shape as Phase 1).
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import boto3
import mongomock
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
# moto requires non-empty creds in env or in the call.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")

from services import ai_pipeline  # noqa: E402
from services import audit as audit_mod  # noqa: E402
from services import aws_waf  # noqa: E402
from services import db as db_mod  # noqa: E402
from services import scoring  # noqa: E402
import main  # noqa: E402


def _fake_explanation(rule: Dict[str, Any]) -> Dict[str, Any]:
    if (rule.get("hit_count") or 0) == 0:
        return {"explanation": "dead", "working": False, "concerns": "zero"}
    return {"explanation": "ok", "working": True, "concerns": None}


def _fake_findings(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    dead_customer = [
        r["rule_name"]
        for r in rules
        if (r.get("hit_count") or 0) == 0 and not r.get("fms_managed")
    ]
    if dead_customer:
        out.append(
            {
                "type": "dead_rule",
                "severity": "medium",
                "affected_rules": dead_customer,
                "title": "dead",
                "description": "zero",
                "recommendation": "remove",
                "confidence": 0.9,
            }
        )
    fms_zero = [
        r["rule_name"]
        for r in rules
        if r.get("fms_managed") and (r.get("hit_count") or 0) == 0
    ]
    for n in fms_zero:
        out.append(
            {
                "type": "fms_review",
                "severity": "low",
                "affected_rules": [n],
                "title": "fms",
                "description": "fms",
                "recommendation": "escalate",
                "confidence": 0.6,
            }
        )
    return out


def _fake_run_pipeline(rules):
    enriched = [{**r, "ai_explanation": _fake_explanation(r)} for r in rules]
    return {"rules": enriched, "findings": _fake_findings(enriched)}


@pytest.fixture(autouse=True)
def _patch(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(ai_pipeline, "run_pipeline", _fake_run_pipeline)
    monkeypatch.setattr(main, "run_pipeline", _fake_run_pipeline)
    mock_db = mongomock.MongoClient()["ruleiq_test"]
    db_mod.set_test_db(mock_db)
    monkeypatch.delenv("DEMO_MODE", raising=False)
    yield mock_db
    db_mod.clear_test_db()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(main.app)


# ---------- DEMO_MODE / hybrid branching --------------------------------------


def test_assume_role_branch_demo_mode_uses_fixtures(_patch, monkeypatch):
    """DEMO_MODE=true wins even when role_arn is supplied → fixture path."""
    monkeypatch.setenv("DEMO_MODE", "true")
    called = {"n": 0}

    def boom(*a, **kw):
        called["n"] += 1
        raise AssertionError("assume_role must NOT be called in DEMO_MODE")

    monkeypatch.setattr(aws_waf, "assume_role", boom)

    audit_id = audit_mod.create_audit_run(
        _patch,
        account_id="111122223333",
        role_arn="arn:aws:iam::111122223333:role/RuleIQAuditRole",
        region="us-east-1",
        log_window_days=30,
        external_id="abc",
    )
    audit_mod.run_audit_pipeline(audit_id, _patch)

    run = _patch["audit_runs"].find_one({"_id": audit_id})
    assert run["status"] == "complete"
    assert run["data_source"] == "fixture"
    assert called["n"] == 0


def test_post_audits_no_role_arn_uses_fixtures(_patch, client, monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    resp = client.post(
        "/api/audits",
        json={"account_id": "111122223333", "region": "us-east-1"},
    )
    assert resp.status_code == 202
    audit_id = resp.json()["audit_run_id"]
    audit_mod.run_audit_pipeline(audit_id, _patch)
    run = _patch["audit_runs"].find_one({"_id": audit_id})
    assert run["data_source"] == "fixture"
    assert run["status"] == "complete"


# ---------- assume_role + real wafv2 path -------------------------------------


def _bootstrap_real_waf(account_id: str = "111122223333") -> tuple[str, str]:
    """Create iam role + ipset + 2 web ACLs (5 rules total) with moto."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName="RuleIQAuditRole",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    role_arn = f"arn:aws:iam::{account_id}:role/RuleIQAuditRole"

    wafv2 = boto3.client("wafv2", region_name="us-east-1")
    ipset = wafv2.create_ip_set(
        Name="ruleiq-test-blocklist",
        Scope="REGIONAL",
        IPAddressVersion="IPV4",
        Addresses=["203.0.113.5/32"],
    )
    ipset_arn = ipset["Summary"]["ARN"]

    common_vis = {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": "x",
    }
    rules_a = [
        {
            "Name": "BlockBadIPs",
            "Priority": 1,
            "Action": {"Block": {}},
            "Statement": {"IPSetReferenceStatement": {"ARN": ipset_arn}},
            "VisibilityConfig": common_vis,
        },
        {
            "Name": "RateLimitGlobal",
            "Priority": 2,
            "Action": {"Block": {}},
            "Statement": {
                "RateBasedStatement": {"Limit": 1000, "AggregateKeyType": "IP"}
            },
            "VisibilityConfig": common_vis,
        },
        {
            "Name": "BlockAdminPath",
            "Priority": 3,
            "Action": {"Block": {}},
            "Statement": {
                "ByteMatchStatement": {
                    "SearchString": "/admin/",
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
                    "PositionalConstraint": "STARTS_WITH",
                }
            },
            "VisibilityConfig": common_vis,
        },
    ]
    rules_b = [
        {
            "Name": "LegacyDeadRule",
            "Priority": 1,
            "Action": {"Block": {}},
            "Statement": {
                "ByteMatchStatement": {
                    "SearchString": "legacy",
                    "FieldToMatch": {"SingleHeader": {"Name": "x-old-header"}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    "PositionalConstraint": "EXACTLY",
                }
            },
            "VisibilityConfig": common_vis,
        },
        {
            "Name": "AllowOffice",
            "Priority": 2,
            "Action": {"Allow": {}},
            "Statement": {"IPSetReferenceStatement": {"ARN": ipset_arn}},
            "VisibilityConfig": common_vis,
        },
    ]
    wafv2.create_web_acl(
        Name="acl-a",
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig=common_vis,
        Rules=rules_a,
    )
    wafv2.create_web_acl(
        Name="acl-b",
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig=common_vis,
        Rules=rules_b,
    )
    return role_arn, ipset_arn


@mock_aws
def test_assume_role_called_when_role_arn_present(_patch, monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    role_arn, _ = _bootstrap_real_waf()

    captured: Dict[str, Any] = {}

    def spy(role, ext_id):
        captured["role"] = role
        captured["ext_id"] = ext_id
        return boto3.Session()

    monkeypatch.setattr(aws_waf, "assume_role", spy)
    # Skip CloudWatch logs lookup so we don't need filter parsing.
    monkeypatch.setattr(aws_waf, "discover_logging", lambda *a, **kw: None)
    monkeypatch.setattr(aws_waf, "enrich_fms", lambda *a, **kw: {"available": False})

    audit_id = audit_mod.create_audit_run(
        _patch,
        account_id="111122223333",
        role_arn=role_arn,
        region="us-east-1",
        log_window_days=30,
        external_id="testextid12345678",
    )
    audit_mod.run_audit_pipeline(audit_id, _patch)
    assert captured["role"] == role_arn
    assert captured["ext_id"] == "testextid12345678"


@mock_aws
def test_real_audit_persists_real_rules(_patch, monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    role_arn, _ = _bootstrap_real_waf()
    # Bypass STS — moto fully mocks the default session for wafv2/logs/fms.
    monkeypatch.setattr(aws_waf, "assume_role", lambda *a, **kw: boto3.Session())
    monkeypatch.setattr(aws_waf, "discover_logging", lambda *a, **kw: None)
    monkeypatch.setattr(aws_waf, "enrich_fms", lambda *a, **kw: {"available": True, "policies": []})

    audit_id = audit_mod.create_audit_run(
        _patch,
        account_id="111122223333",
        role_arn=role_arn,
        region="us-east-1",
        log_window_days=30,
        external_id="testextid12345678",
    )
    audit_mod.run_audit_pipeline(audit_id, _patch)

    run = _patch["audit_runs"].find_one({"_id": audit_id})
    assert run["status"] == "complete", run.get("failure_reason")
    assert run["data_source"] == "aws"
    assert run["rule_count"] == 5
    assert run["web_acl_count"] == 2
    assert run["fms_visibility"] is True
    assert _patch["rules"].count_documents({"audit_run_id": audit_id}) == 5


@mock_aws
def test_logging_unavailable_marks_metadata_and_zeroes_hits(_patch, monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    role_arn, _ = _bootstrap_real_waf()
    monkeypatch.setattr(aws_waf, "assume_role", lambda *a, **kw: boto3.Session())
    monkeypatch.setattr(aws_waf, "discover_logging", lambda *a, **kw: None)
    monkeypatch.setattr(aws_waf, "enrich_fms", lambda *a, **kw: {"available": False})

    audit_id = audit_mod.create_audit_run(
        _patch,
        account_id="111122223333",
        role_arn=role_arn,
        region="us-east-1",
        log_window_days=30,
        external_id="ext1",
    )
    audit_mod.run_audit_pipeline(audit_id, _patch)
    run = _patch["audit_runs"].find_one({"_id": audit_id})
    assert run["logging_available"] is False
    for r in _patch["rules"].find({"audit_run_id": audit_id}):
        assert r["hit_count"] == 0


@mock_aws
def test_fms_access_denied_silent_skip(_patch, monkeypatch):
    """enrich_fms swallows AccessDenied and returns available=False."""
    monkeypatch.delenv("DEMO_MODE", raising=False)
    role_arn, _ = _bootstrap_real_waf()
    monkeypatch.setattr(aws_waf, "assume_role", lambda *a, **kw: boto3.Session())
    monkeypatch.setattr(aws_waf, "discover_logging", lambda *a, **kw: None)

    from botocore.exceptions import ClientError

    def _denied(session, account_id, region):
        # Simulate the silent-degrade path inside enrich_fms.
        try:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListPolicies",
            )
        except ClientError:
            return {"available": False}

    monkeypatch.setattr(aws_waf, "enrich_fms", _denied)

    audit_id = audit_mod.create_audit_run(
        _patch, "111122223333", role_arn, "us-east-1", 30, external_id="ext1"
    )
    audit_mod.run_audit_pipeline(audit_id, _patch)
    run = _patch["audit_runs"].find_one({"_id": audit_id})
    assert run["status"] == "complete"
    assert run["fms_visibility"] is False


# ---------- get_rule_stats (fake logs client) --------------------------------


class _FakeLogsClient:
    """Returns canned events for filter_log_events; honors max_events cap."""

    def __init__(self, events: List[Dict[str, Any]]):
        self._events = events

    def filter_log_events(self, **kwargs):
        # Single page, no nextToken.
        limit = kwargs.get("limit", 1000)
        return {"events": self._events[:limit]}


def test_get_rule_stats_parses_uris_and_counts():
    now_ms = int(time.time() * 1000)
    events = [
        {
            "timestamp": now_ms - 1000,
            "message": json.dumps(
                {
                    "action": "BLOCK",
                    "terminatingRuleId": "BlockBadIPs",
                    "httpRequest": {"uri": "/login"},
                }
            ),
        },
        {
            "timestamp": now_ms,
            "message": json.dumps(
                {
                    "action": "COUNT",
                    "terminatingRuleId": "BlockBadIPs",
                    "httpRequest": {"uri": "/api/v1"},
                }
            ),
        },
        {
            "timestamp": now_ms - 5000,
            "message": json.dumps(
                {
                    "action": "BLOCK",
                    "terminatingRuleId": "BlockBadIPs",
                    "httpRequest": {"uri": "/login"},  # dup, should dedupe
                }
            ),
        },
    ]
    fake = _FakeLogsClient(events)
    out = aws_waf.get_rule_stats(
        session=None,
        log_group_arn="arn:aws:logs:us-east-1:111:log-group:lg:*",
        rule_name="BlockBadIPs",
        web_acl_name="acl-a",
        days=30,
        max_events=10,
        logs_client=fake,
    )
    assert out["hit_count"] == 3
    assert out["count_mode_hits"] == 1
    assert out["sample_uris"] == ["/api/v1", "/login"]
    assert out["last_fired"] is not None


# ---------- /api/setup-info ---------------------------------------------------


def test_setup_info_returns_quick_create_url_with_external_id(client):
    resp = client.get("/api/setup-info?account_id=123456789012")
    assert resp.status_code == 200
    body = resp.json()
    assert body["app_runner_account_id"] == "371126261144"
    assert body["account_id"] == "123456789012"
    assert len(body["external_id"]) == 32
    assert body["cfn_template_url"].endswith("/customer-role.yaml")
    assert "templateURL=" in body["cfn_quick_create_url"]
    assert "param_RuleIQTrustedAccount=371126261144" in body["cfn_quick_create_url"]
    assert f"param_ExternalId={body['external_id']}" in body["cfn_quick_create_url"]
    assert body["inline_iam_json"]["Version"] == "2012-10-17"


def test_setup_info_quick_create_uses_question_mark_separator(client):
    body = client.get("/api/setup-info?account_id=123456789012").json()
    url = body["cfn_quick_create_url"]
    assert "quickcreate?templateURL=" in url, url
    assert "quickcreate&templateURL=" not in url, url


def test_setup_info_external_id_is_stable(client):
    """Phase 3 hot-fix: deterministic per-account_id ExternalId."""
    a = client.get("/api/setup-info?account_id=123456789012").json()["external_id"]
    b = client.get("/api/setup-info?account_id=123456789012").json()["external_id"]
    c = client.get("/api/setup-info?account_id=123456789012").json()["external_id"]
    assert a == b == c
    assert len(a) == 32


# ---------- Scoring breakdown -------------------------------------------------


def test_estimated_waste_breakdown_per_rule():
    rules = [
        {"rule_name": "DeadA", "hit_count": 0, "fms_managed": False},
        {"rule_name": "DeadB", "hit_count": 0, "fms_managed": False},
        {"rule_name": "FmsDead", "hit_count": 0, "fms_managed": True},
        {"rule_name": "Live", "hit_count": 50, "fms_managed": False},
    ]
    breakdown = scoring.estimated_waste_breakdown(rules)
    waste = scoring.estimated_waste_usd(rules)
    names = [b["rule_name"] for b in breakdown]
    assert names == ["DeadA", "DeadB"]
    assert sum(b["monthly_usd"] for b in breakdown) == waste


# ---------- Audit POST schema -------------------------------------------------


def test_audit_create_request_no_external_id_field(client):
    """external_id MUST NOT be in the request body — server recomputes it."""
    resp = client.post(
        "/api/audits",
        json={
            "account_id": "111122223333",
            "role_arn": None,
            "region": "us-east-1",
        },
    )
    assert resp.status_code == 202
    # And providing an external_id is silently ignored (extra="ignore").
    resp2 = client.post(
        "/api/audits",
        json={
            "account_id": "111122223333",
            "role_arn": None,
            "external_id": "client-supplied-garbage",
            "region": "us-east-1",
        },
    )
    assert resp2.status_code == 202


# ---------- _normalize_for_json (regression for "bytes is not JSON serializable") ----


def test_normalize_for_json_handles_bytes_and_datetimes():
    from datetime import datetime, timezone
    payload = {
        "SearchString": b"/admin/",                  # utf-8 → string
        "BinaryBlob": b"\x80\x81\x82\xff",           # not utf-8 → base64
        "Nested": [
            {"FieldToMatch": {"UriPath": {}}},
            b"raw-bytes",
        ],
        "Tuple": (b"a", b"b"),
        "When": datetime(2026, 2, 16, 12, 0, tzinfo=timezone.utc),
        "PassThrough": 42,
    }
    out = aws_waf._normalize_for_json(payload)
    assert out["SearchString"] == "/admin/"
    assert out["BinaryBlob"] == "gIGC/w=="           # base64 of 0x80 0x81 0x82 0xff
    assert out["Nested"][0] == {"FieldToMatch": {"UriPath": {}}}
    assert out["Nested"][1] == "raw-bytes"
    assert out["Tuple"] == ["a", "b"]
    assert out["When"] == "2026-02-16T12:00:00+00:00"
    assert out["PassThrough"] == 42
    # Round-trip: must JSON-serialize without error.
    json.dumps(out)


@mock_aws
def test_get_web_acl_rules_normalizes_byte_match_statement(_patch, monkeypatch):
    """Real boto3 returns ByteMatchStatement.SearchString as bytes — must be string after normalize."""
    monkeypatch.setattr(aws_waf, "assume_role", lambda *a, **kw: boto3.Session())
    role_arn, _ = _bootstrap_real_waf()  # creates acl-a (rules incl. BlockAdminPath ByteMatch)
    session = boto3.Session()
    acls = aws_waf.list_web_acls(session, "us-east-1")
    target = next(a for a in acls if a["Name"] == "acl-a")
    rules = aws_waf.get_web_acl_rules(session, target)

    bm = next((r for r in rules if r["rule_name"] == "BlockAdminPath"), None)
    assert bm is not None
    stmt = bm["statement_json"]
    search = stmt["ByteMatchStatement"]["SearchString"]
    assert isinstance(search, str), f"expected str, got {type(search).__name__}"
    assert search == "/admin/"
    # Whole statement must JSON-serialize (no bytes anywhere)
    json.dumps(stmt)


def test_data_source_set_to_aws_before_load(_patch, monkeypatch):
    """Even if the AWS load throws mid-flight, data_source must be 'aws' (not 'pending')."""
    monkeypatch.delenv("DEMO_MODE", raising=False)

    def boom(*a, **kw):
        raise RuntimeError("simulated assume_role failure")
    monkeypatch.setattr(aws_waf, "assume_role", boom)

    audit_id = audit_mod.create_audit_run(
        _patch, "111122223333",
        role_arn="arn:aws:iam::111122223333:role/RuleIQAuditRole",
        region="us-east-1", log_window_days=30, external_id="ext1",
    )
    audit_mod.run_audit_pipeline(audit_id, _patch)
    run = _patch["audit_runs"].find_one({"_id": audit_id})
    assert run["status"] == "failed"
    assert run["data_source"] == "aws", (
        f"expected data_source='aws' on real-path failure, got {run['data_source']!r}"
    )


def test_data_source_set_to_fixture_for_demo_mode(_patch, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    audit_id = audit_mod.create_audit_run(
        _patch, "111122223333", "arn:fake", "us-east-1", 30, external_id="x"
    )
    audit_mod.run_audit_pipeline(audit_id, _patch)
    run = _patch["audit_runs"].find_one({"_id": audit_id})
    assert run["data_source"] == "fixture"
