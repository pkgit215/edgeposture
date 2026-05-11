"""Phase 5 PRODUCTION integration tests.

The Phase 5/5.5 unit tests previously passed against synthetic fixtures
while production was broken in 4 places. These tests simulate the EXACT
real-AWS shapes (boto3 WAFv2 + CloudWatch Logs) so any drift between
"test world" and "production world" is caught here first.

Specifically asserts (Task C from the production-fix spec):
  1. derive_mode for ManagedRuleGroupStatement w/ OverrideAction={None:{}}
     produces "Block (group)" AND that value reaches the persisted Rule doc.
  2. When list_resources_for_web_acl returns [] for a REGIONAL ACL, an
     `orphaned_web_acl` finding is emitted AND that ACL's `dead_rule`
     findings are suppressed.
  3. Shellshock UA in `httpRequest.headers` is detected → score >= 10.
  4. URL-encoded `<script>` in `args` is detected after decoding → score >= XSS.
  5. `web_acls` array is populated on the AuditRun.
  6. AccessDenied on list_resources_for_web_acl does NOT produce
     false-positive orphan findings (attached=None / Unknown).
  7. CloudFront ACL with empty list_resources_for_web_acl response is
     treated as UNKNOWN, not orphan.
  8. Debug log sample is captured on the audit run.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import mongomock
import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)

from services import ai_pipeline  # noqa: E402
from services import audit as audit_mod  # noqa: E402
from services import aws_waf  # noqa: E402
from services import db as db_mod  # noqa: E402
import main  # noqa: E402


# --- Real-shape AWS fixtures (sanitised from real boto3 responses) ---------

REGIONAL_ACL_ARN = "arn:aws:wafv2:us-east-1:371126261144:regional/webacl/ruleiq-test-acl/abc-123"
CLOUDFRONT_ACL_ARN = "arn:aws:wafv2:us-east-1:371126261144:global/webacl/ruleiq-cf-acl/def-456"
ALB_ARN = "arn:aws:elasticloadbalancing:us-east-1:371126261144:loadbalancer/app/ruleiq-test-alb/abc"
LOG_GROUP_ARN = "arn:aws:logs:us-east-1:371126261144:log-group:aws-waf-logs-ruleiq-cf-test:*"
LOG_GROUP_NAME = "aws-waf-logs-ruleiq-cf-test"


WEB_ACL_REGIONAL_RESPONSE = {
    "WebACL": {
        "Name": "ruleiq-test-acl",
        "Id": "abc-123",
        "ARN": REGIONAL_ACL_ARN,
        "Description": "Test ACL",
        "DefaultAction": {"Allow": {}},
        "Scope": "REGIONAL",
        "Rules": [
            # Direct managed-rule-group reference — the case that
            # previously rendered as "ALLOW" in the PDF.
            {
                "Name": "AWS-AWSManagedRulesAmazonIpReputationList",
                "Priority": 0,
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesAmazonIpReputationList",
                    }
                },
                "OverrideAction": {"None": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "AmazonIpReputationList",
                },
            },
            {
                "Name": "AWS-AWSManagedRulesCommonRuleSet",
                "Priority": 1,
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesCommonRuleSet",
                    }
                },
                "OverrideAction": {"Count": {}},  # operator put in count mode
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "CommonRuleSet",
                },
            },
            # A custom block rule that will appear as `dead_rule` in tests.
            {
                "Name": "Block-Test-IP",
                "Priority": 10,
                "Statement": {
                    "ByteMatchStatement": {
                        "SearchString": b"/admin",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "STARTS_WITH",
                    }
                },
                "Action": {"Block": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "BlockTestIP",
                },
            },
        ],
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "ruleiq-test-acl",
        },
        "Capacity": 700,
        "ManagedByFirewallManager": False,
    }
}

CLOUDFRONT_ACL_RESPONSE = {
    "WebACL": {
        "Name": "ruleiq-cf-acl",
        "Id": "def-456",
        "ARN": CLOUDFRONT_ACL_ARN,
        "DefaultAction": {"Allow": {}},
        "Scope": "CLOUDFRONT",
        "Rules": [
            {
                "Name": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
                "Priority": 0,
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesKnownBadInputsRuleSet",
                    }
                },
                "OverrideAction": {"None": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "KnownBadInputs",
                },
            },
        ],
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "ruleiq-cf-acl",
        },
        "Capacity": 200,
        "ManagedByFirewallManager": False,
    }
}


# Real WAFv2 CloudWatch Logs event shapes (exactly as user pasted).
def _shellshock_event() -> Dict[str, Any]:
    return {
        "timestamp": 1715450000000,
        "message": json.dumps({
            "timestamp": 1715450000000,
            "formatVersion": 1,
            "webaclId": CLOUDFRONT_ACL_ARN,
            "terminatingRuleId": "Default_Action",
            "terminatingRuleType": "REGULAR",
            "action": "ALLOW",
            "httpSourceName": "CF",
            "httpSourceId": "EKOXAVPA9GX2R",
            "httpRequest": {
                "clientIp": "192.0.2.1",
                "country": "RU",
                "headers": [
                    {"name": "host", "value": "aitrading.ninja"},
                    {"name": "user-agent", "value": '() { :;}; /bin/bash -c "echo hacked"'},
                    {"name": "accept", "value": "*/*"},
                ],
                "uri": "/",
                "args": "",
                "httpVersion": "HTTP/2.0",
                "httpMethod": "GET",
                "requestId": "req-shellshock",
            },
        })
    }


def _url_encoded_xss_event() -> Dict[str, Any]:
    return {
        "timestamp": 1715450001000,
        "message": json.dumps({
            "timestamp": 1715450001000,
            "formatVersion": 1,
            "webaclId": CLOUDFRONT_ACL_ARN,
            "terminatingRuleId": "Default_Action",
            "terminatingRuleType": "REGULAR",
            "action": "ALLOW",
            "httpSourceName": "CF",
            "httpSourceId": "EKOXAVPA9GX2R",
            "httpRequest": {
                "clientIp": "203.0.113.5",
                "country": "US",
                "headers": [
                    {"name": "host", "value": "aitrading.ninja"},
                    {"name": "user-agent", "value": "Mozilla/5.0"},
                ],
                # PRODUCTION shape: URL-encoded.
                "uri": "/search",
                "args": "q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
                "httpVersion": "HTTP/2.0",
                "httpMethod": "GET",
                "requestId": "req-xss",
            },
        })
    }


def _benign_event() -> Dict[str, Any]:
    return {
        "timestamp": 1715450002000,
        "message": json.dumps({
            "timestamp": 1715450002000,
            "formatVersion": 1,
            "webaclId": CLOUDFRONT_ACL_ARN,
            "terminatingRuleId": "Default_Action",
            "terminatingRuleType": "REGULAR",
            "action": "ALLOW",
            "httpSourceName": "CF",
            "httpSourceId": "EKOXAVPA9GX2R",
            "httpRequest": {
                "clientIp": "198.51.100.1",
                "country": "US",
                "headers": [
                    {"name": "host", "value": "aitrading.ninja"},
                    {"name": "user-agent", "value": "Mozilla/5.0 (Macintosh)"},
                ],
                "uri": "/",
                "args": "",
                "httpVersion": "HTTP/2.0",
                "httpMethod": "GET",
                "requestId": "req-benign",
            },
        })
    }


# --- Mock boto3 session -----------------------------------------------------


class _MockWafv2Client:
    """boto3 WAFv2 client returning the real-shape responses above."""

    def __init__(self, mode: str):
        # mode: "regional_attached" | "regional_orphan" | "regional_access_denied"
        self.mode = mode
        self.calls: List[Dict[str, Any]] = []

    def get_web_acl(self, **kwargs):
        self.calls.append(("get_web_acl", kwargs))
        scope = kwargs.get("Scope")
        if scope == "CLOUDFRONT":
            return CLOUDFRONT_ACL_RESPONSE
        return WEB_ACL_REGIONAL_RESPONSE

    def list_resources_for_web_acl(self, **kwargs):
        self.calls.append(("list_resources_for_web_acl", kwargs))
        arn = kwargs["WebACLArn"]
        rt = kwargs.get("ResourceType")
        if self.mode == "regional_access_denied":
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListResourcesForWebACL",
            )
        if arn == CLOUDFRONT_ACL_ARN:
            # CloudFront returns empty even when attached (the unreliable case)
            return {"ResourceArns": []}
        if self.mode == "regional_orphan":
            return {"ResourceArns": []}
        # regional_attached: ALB only
        if rt == "APPLICATION_LOAD_BALANCER":
            return {"ResourceArns": [ALB_ARN]}
        return {"ResourceArns": []}

    def get_logging_configuration(self, **kwargs):
        return {
            "LoggingConfiguration": {
                "ResourceArn": kwargs["ResourceArn"],
                "LogDestinationConfigs": [LOG_GROUP_ARN],
            }
        }


class _MockLogsClient:
    """boto3 logs client returning ALLOW events with mixed shapes."""

    def __init__(self, events: List[Dict[str, Any]]):
        self.events = events
        self.calls: List[Dict[str, Any]] = []

    def filter_log_events(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs.get("nextToken"):
            return {"events": [], "nextToken": None}
        # Honour server-side ALLOW filter pattern
        pattern = kwargs.get("filterPattern", "")
        filtered = []
        for ev in self.events:
            parsed = json.loads(ev["message"])
            if '$.action = "ALLOW"' in pattern and parsed.get("action") != "ALLOW":
                continue
            filtered.append(ev)
        return {"events": filtered, "nextToken": None}


class _MockSession:
    def __init__(self, wafv2_mode="regional_attached", events=None):
        self.wafv2 = _MockWafv2Client(wafv2_mode)
        self.logs = _MockLogsClient(events or [])

    def client(self, service, region_name=None):
        if service == "wafv2":
            return self.wafv2
        if service == "logs":
            return self.logs
        raise NotImplementedError(service)


# --- Fixtures ---------------------------------------------------------------


@pytest.fixture()
def db():
    mock = mongomock.MongoClient()["ruleiq_phase5_integration"]
    db_mod.set_test_db(mock)
    yield mock
    db_mod.clear_test_db()


@pytest.fixture()
def client(db) -> TestClient:
    return TestClient(main.app)


def _patch_aws_path(monkeypatch, *, web_acls_meta, mock_session, mock_pipeline=True):
    """Patch the AWS-path entry points so we never hit real boto3 / OpenAI."""
    monkeypatch.setattr(aws_waf, "assume_role", lambda *_a, **_kw: mock_session)
    monkeypatch.setattr(aws_waf, "list_web_acls", lambda *_a, **_kw: web_acls_meta)
    monkeypatch.setattr(
        aws_waf, "enrich_fms",
        lambda *_a, **_kw: {"available": False, "policies": []},
    )
    monkeypatch.setattr(
        aws_waf, "get_rule_stats",
        lambda *_a, **_kw: {"hit_count": 0, "last_fired": None, "count_mode_hits": 0, "sample_uris": []},
    )
    monkeypatch.setattr(aws_waf, "discover_logging", lambda *_a, **_kw: LOG_GROUP_ARN)
    monkeypatch.setenv("DEMO_MODE", "false")
    if mock_pipeline:
        def fake_run_pipeline(rules, suspicious_requests=None):
            enriched = [{**r, "ai_explanation": {"explanation": "m", "working": True, "concerns": None}} for r in rules]
            findings = [
                {
                    "type": "dead_rule",
                    "severity": "high",
                    "affected_rules": [r["rule_name"] for r in rules if not r.get("fms_managed")],
                    "title": "Zero hits across the audit",
                    "description": "—",
                    "recommendation": "—",
                    "confidence": 0.9,
                }
            ]
            if suspicious_requests:
                findings.append({
                    "type": "bypass_candidate",
                    "severity": "high",
                    "affected_rules": [],
                    "title": "Possible WAF bypass: shellshock reached origin",
                    "description": "Sample shellshock UA",
                    "recommendation": "Enable KnownBadInputs.",
                    "confidence": 0.92,
                    "evidence": "log-sample",
                })
            return {"rules": enriched, "findings": findings}
        monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline", fake_run_pipeline)


# --- Tests ------------------------------------------------------------------


def test_derive_mode_managed_with_override_none_against_real_shape():
    """Task C #1: feed the EXACT boto3 response into get_web_acl_rules and
    check the projected rule has action='Block (group)'."""
    sess = _MockSession()
    rules = aws_waf.get_web_acl_rules(
        sess, {"Name": "ruleiq-test-acl", "Id": "abc-123", "Scope": "REGIONAL", "ARN": REGIONAL_ACL_ARN}
    )
    iprep = next(r for r in rules if "IpReputation" in r["rule_name"])
    assert iprep["action"] == "Block (group)", f"got action={iprep['action']!r}"
    assert iprep["rule_kind"] == "managed"
    # OverrideAction Count must produce "Count (override)"
    crs = next(r for r in rules if "CommonRuleSet" in r["rule_name"])
    assert crs["action"] == "Count (override)"
    # Custom block rule stays uppercase
    blk = next(r for r in rules if r["rule_name"] == "Block-Test-IP")
    assert blk["action"] == "BLOCK"
    assert blk["rule_kind"] == "custom"


def test_derive_mode_propagates_to_persisted_rule_doc(client, db, monkeypatch):
    """Task C #1 end-to-end: action='Block (group)' must reach Mongo."""
    sess = _MockSession()
    _patch_aws_path(
        monkeypatch,
        web_acls_meta=[
            {"Name": "ruleiq-test-acl", "Id": "abc-123", "Scope": "REGIONAL", "ARN": REGIONAL_ACL_ARN, "Region": "us-east-1"},
        ],
        mock_session=sess,
    )
    audit_id = audit_mod.create_audit_run(
        db=db, account_id="371126261144",
        role_arn="arn:aws:iam::371126261144:role/ruleiq-audit",
        region="us-east-1", log_window_days=30, external_id="x" * 64,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    iprep = db["rules"].find_one({
        "audit_run_id": audit_id,
        "rule_name": "AWS-AWSManagedRulesAmazonIpReputationList",
    })
    assert iprep is not None, "managed rule was not persisted"
    assert iprep["action"] == "Block (group)"
    assert iprep["rule_kind"] == "managed"


def test_orphan_acl_emits_finding_and_suppresses_dead_rules(client, db, monkeypatch):
    """Task C #2: empty list_resources_for_web_acl → orphaned_web_acl finding
    AND dead_rule findings for rules in that ACL are suppressed."""
    sess = _MockSession(wafv2_mode="regional_orphan")
    _patch_aws_path(
        monkeypatch,
        web_acls_meta=[
            {"Name": "ruleiq-test-acl", "Id": "abc-123", "Scope": "REGIONAL", "ARN": REGIONAL_ACL_ARN, "Region": "us-east-1"},
        ],
        mock_session=sess,
    )
    audit_id = audit_mod.create_audit_run(
        db=db, account_id="371126261144",
        role_arn="arn:aws:iam::371126261144:role/ruleiq-audit",
        region="us-east-1", log_window_days=30, external_id="x" * 64,
    )
    audit_mod.run_audit_pipeline(audit_id, db)

    findings = list(db["findings"].find({"audit_run_id": audit_id}))
    types = [f["type"] for f in findings]

    # 1) Orphan finding emitted
    orphan = [f for f in findings if f["type"] == "orphaned_web_acl"]
    assert orphan, f"expected orphaned_web_acl finding; got types={types}"
    assert "ruleiq-test-acl" in orphan[0]["title"]

    # 2) Dead-rule findings for rules in the orphan ACL are suppressed
    dead = [f for f in findings if f["type"] == "dead_rule"]
    for f in dead:
        assert "Block-Test-IP" not in f["affected_rules"], (
            f"dead_rule for rule in orphan ACL was not suppressed: {f}"
        )


def test_access_denied_does_not_produce_false_orphan(client, db, monkeypatch):
    """Task C #6: IAM AccessDenied on list_resources_for_web_acl must NOT
    produce a false-positive orphan finding."""
    sess = _MockSession(wafv2_mode="regional_access_denied")
    _patch_aws_path(
        monkeypatch,
        web_acls_meta=[
            {"Name": "ruleiq-test-acl", "Id": "abc-123", "Scope": "REGIONAL", "ARN": REGIONAL_ACL_ARN, "Region": "us-east-1"},
        ],
        mock_session=sess,
    )
    audit_id = audit_mod.create_audit_run(
        db=db, account_id="371126261144",
        role_arn="arn:aws:iam::371126261144:role/ruleiq-audit",
        region="us-east-1", log_window_days=30, external_id="x" * 64,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    findings = list(db["findings"].find({"audit_run_id": audit_id}))
    orphan = [f for f in findings if f["type"] == "orphaned_web_acl"]
    assert not orphan, "AccessDenied should not produce an orphan finding"
    # The ACL summary should mark attached=None (unknown)
    run = db["audit_runs"].find_one({"_id": audit_id})
    assert run["web_acls"][0]["attached"] is None


def test_cloudfront_empty_attachment_is_unknown_not_orphan(client, db, monkeypatch):
    """Task C #7: CloudFront ACL with empty resource list (the WAFv2 API's
    unreliable case) must be UNKNOWN, not orphan."""
    sess = _MockSession()
    _patch_aws_path(
        monkeypatch,
        web_acls_meta=[
            {"Name": "ruleiq-cf-acl", "Id": "def-456", "Scope": "CLOUDFRONT", "ARN": CLOUDFRONT_ACL_ARN},
        ],
        mock_session=sess,
    )
    audit_id = audit_mod.create_audit_run(
        db=db, account_id="371126261144",
        role_arn="arn:aws:iam::371126261144:role/ruleiq-audit",
        region="us-east-1", log_window_days=30, external_id="x" * 64,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    run = db["audit_runs"].find_one({"_id": audit_id})
    cf = next(a for a in run["web_acls"] if a["name"] == "ruleiq-cf-acl")
    assert cf["attached"] is None, "CloudFront empty-resources must map to UNKNOWN"
    findings = list(db["findings"].find({"audit_run_id": audit_id, "type": "orphaned_web_acl"}))
    assert not findings


def test_shellshock_in_real_waf_log_shape_detected():
    """Task C #3: real-shape shellshock UA → score >= 10."""
    parsed = json.loads(_shellshock_event()["message"])
    score = aws_waf.score_request_suspicion(parsed)
    assert score >= 10, f"shellshock should score >= 10, got {score}"


def test_url_encoded_xss_detected_after_decoding():
    """Task C #4: URL-encoded <script> in args must be detected."""
    parsed = json.loads(_url_encoded_xss_event()["message"])
    score = aws_waf.score_request_suspicion(parsed)
    assert score >= aws_waf._S_XSS, (
        f"URL-encoded XSS in args must be detected (decoded), got {score}"
    )


def test_web_acls_populated_on_audit_run(client, db, monkeypatch):
    """Task C #5: web_acls array on AuditRun is populated with attachment."""
    sess = _MockSession()  # regional attached
    _patch_aws_path(
        monkeypatch,
        web_acls_meta=[
            {"Name": "ruleiq-test-acl", "Id": "abc-123", "Scope": "REGIONAL", "ARN": REGIONAL_ACL_ARN, "Region": "us-east-1"},
            {"Name": "ruleiq-cf-acl", "Id": "def-456", "Scope": "CLOUDFRONT", "ARN": CLOUDFRONT_ACL_ARN},
        ],
        mock_session=sess,
    )
    audit_id = audit_mod.create_audit_run(
        db=db, account_id="371126261144",
        role_arn="arn:aws:iam::371126261144:role/ruleiq-audit",
        region="us-east-1", log_window_days=30, external_id="x" * 64,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    run = db["audit_runs"].find_one({"_id": audit_id})
    assert "web_acls" in run and isinstance(run["web_acls"], list)
    assert len(run["web_acls"]) == 2
    names = {a["name"] for a in run["web_acls"]}
    assert names == {"ruleiq-test-acl", "ruleiq-cf-acl"}
    # Regional attached → attached True with ALB resource
    regional = next(a for a in run["web_acls"] if a["name"] == "ruleiq-test-acl")
    assert regional["attached"] is True
    assert ALB_ARN in regional["attached_resources"]
    # CloudFront → unknown
    cf = next(a for a in run["web_acls"] if a["name"] == "ruleiq-cf-acl")
    assert cf["attached"] is None
    # Scopes recorded
    assert set(run.get("scopes") or []) == {"REGIONAL", "CLOUDFRONT"}


def test_end_to_end_real_shape_log_event_produces_bypass_candidate(client, db, monkeypatch):
    """Full pipeline: real-shape shellshock event flows through sampler →
    Pass 3 (mocked) → bypass_candidate finding with evidence='log-sample'.
    """
    events = [_shellshock_event(), _url_encoded_xss_event(), _benign_event()]
    sess = _MockSession(events=events)
    _patch_aws_path(
        monkeypatch,
        web_acls_meta=[
            {"Name": "ruleiq-cf-acl", "Id": "def-456", "Scope": "CLOUDFRONT", "ARN": CLOUDFRONT_ACL_ARN},
        ],
        mock_session=sess,
    )
    audit_id = audit_mod.create_audit_run(
        db=db, account_id="371126261144",
        role_arn="arn:aws:iam::371126261144:role/ruleiq-audit",
        region="us-east-1", log_window_days=30, external_id="x" * 64,
    )
    audit_mod.run_audit_pipeline(audit_id, db)

    run = db["audit_runs"].find_one({"_id": audit_id})
    # Suspicious sample populated (shellshock + url-encoded XSS, NOT benign)
    sample = run.get("suspicious_request_sample") or []
    assert len(sample) >= 2, f"expected >=2 suspicious-allow samples, got {len(sample)}"
    request_ids = {s["httpRequest"]["requestId"] for s in sample}
    assert "req-shellshock" in request_ids
    assert "req-xss" in request_ids
    assert "req-benign" not in request_ids

    # Debug log dump persisted
    debug = run.get("debug_log_sample") or []
    assert 1 <= len(debug) <= 5
    assert debug[0]["event"]["httpRequest"]["requestId"]  # parsed JSON

    # bypass_candidate finding emitted with evidence='log-sample'
    bypass = list(db["findings"].find({
        "audit_run_id": audit_id, "type": "bypass_candidate"
    }))
    assert bypass, "expected bypass_candidate finding when suspicious_requests present"
    assert bypass[0]["evidence"] == "log-sample"


def test_scope_field_shows_both_when_both_scopes_present(client, db, monkeypatch):
    """Production-fix task A.6: scopes list should include both."""
    sess = _MockSession()
    _patch_aws_path(
        monkeypatch,
        web_acls_meta=[
            {"Name": "ruleiq-test-acl", "Id": "abc-123", "Scope": "REGIONAL", "ARN": REGIONAL_ACL_ARN, "Region": "us-east-1"},
            {"Name": "ruleiq-cf-acl", "Id": "def-456", "Scope": "CLOUDFRONT", "ARN": CLOUDFRONT_ACL_ARN},
        ],
        mock_session=sess,
    )
    audit_id = audit_mod.create_audit_run(
        db=db, account_id="371126261144",
        role_arn="arn:aws:iam::371126261144:role/ruleiq-audit",
        region="us-east-1", log_window_days=30, external_id="x" * 64,
    )
    audit_mod.run_audit_pipeline(audit_id, db)
    run = db["audit_runs"].find_one({"_id": audit_id})
    scopes = set(run.get("scopes") or [])
    assert scopes == {"REGIONAL", "CLOUDFRONT"}


def test_pdf_renders_web_acl_section_against_real_shape_audit(client, db, monkeypatch):
    """Production task A.5: ensure PDF actually emits the Web ACLs section
    when the audit was real-AWS."""
    from services.pdf_report import render_audit_pdf
    from pypdf import PdfReader
    import io

    sess = _MockSession()
    _patch_aws_path(
        monkeypatch,
        web_acls_meta=[
            {"Name": "ruleiq-test-acl", "Id": "abc-123", "Scope": "REGIONAL", "ARN": REGIONAL_ACL_ARN, "Region": "us-east-1"},
        ],
        mock_session=sess,
    )
    audit_id = audit_mod.create_audit_run(
        db=db, account_id="371126261144",
        role_arn="arn:aws:iam::371126261144:role/ruleiq-audit",
        region="us-east-1", log_window_days=30, external_id="x" * 64,
    )
    audit_mod.run_audit_pipeline(audit_id, db)

    run = db["audit_runs"].find_one({"_id": audit_id})
    rules = list(db["rules"].find({"audit_run_id": audit_id}))
    findings = list(db["findings"].find({"audit_run_id": audit_id}))
    pdf_bytes = render_audit_pdf(run, rules, findings)
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
    assert "Web ACL Attachment" in text
    assert "ruleiq-test-acl" in text
    # Mode column must say "Block (group)" not "ALLOW" for the managed rule
    assert "Block (group)" in text, "PDF mode column missing 'Block (group)' label"
