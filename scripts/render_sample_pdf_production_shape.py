"""Re-render /app/dist/sample-audit.pdf using the EXACT real-AWS shape data
from `tests/test_phase5_integration.py`.

Unlike `render_sample_pdf.py` which uses a synthetic fixture, this script
goes through the same `run_audit_pipeline` path that production uses
(with the real-shape mock boto3 + CloudWatch clients), so the resulting
PDF is byte-for-byte representative of what a real audit will produce.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
TESTS_DIR = BACKEND_DIR / "tests"
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(TESTS_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)
os.environ["DEMO_MODE"] = "false"

import mongomock

from services import audit as audit_mod
from services import aws_waf
from services import db as db_mod
from services.pdf_report import render_audit_pdf

# Reuse the real-shape fixtures + mock session from the integration tests.
from test_phase5_integration import (
    _MockSession,
    _shellshock_event,
    _url_encoded_xss_event,
    _benign_event,
    REGIONAL_ACL_ARN,
    CLOUDFRONT_ACL_ARN,
    ALB_ARN,
    LOG_GROUP_ARN,
)


def main():
    db = mongomock.MongoClient()["ruleiq_sample"]
    db_mod.set_test_db(db)

    events = [
        _shellshock_event(),
        _url_encoded_xss_event(),
        _benign_event(),
    ]
    sess = _MockSession(events=events)
    aws_waf.assume_role = lambda *_a, **_kw: sess
    aws_waf.list_web_acls = lambda *_a, **_kw: [
        {"Name": "ruleiq-test-acl", "Id": "abc-123", "Scope": "REGIONAL",
         "ARN": REGIONAL_ACL_ARN, "Region": "us-east-1"},
        {"Name": "ruleiq-cf-acl", "Id": "def-456", "Scope": "CLOUDFRONT",
         "ARN": CLOUDFRONT_ACL_ARN},
    ]
    aws_waf.enrich_fms = lambda *_a, **_kw: {"available": True, "policies": []}
    # Synthesise hit counts: zero for the managed groups so they show in
    # the inventory as "Block (group)" with hit_count=0 (the production
    # case the user reported).
    aws_waf.get_rule_stats = lambda *_a, **_kw: {
        "hit_count": 0, "last_fired": None, "count_mode_hits": 0, "sample_uris": []
    }
    aws_waf.discover_logging = lambda *_a, **_kw: LOG_GROUP_ARN

    # Mock the LLM pipeline so we don't call OpenAI. We construct realistic
    # findings that exercise every section.
    def fake_run_pipeline(rules, suspicious_requests=None):
        enriched = [
            {**r, "ai_explanation": {
                "explanation": (
                    f"This rule ({r['rule_name']}) protects the application "
                    f"against the OWASP-class threats indicated by its "
                    f"statement type."
                ),
                "working": (r.get("hit_count") or 0) > 0,
                "concerns": None if (r.get("hit_count") or 0) > 0
                            else "Zero hits in the audit window.",
            }}
            for r in rules
        ]
        findings = []
        for r in rules:
            if not r.get("fms_managed") and (r.get("hit_count") or 0) == 0 and r["rule_kind"] == "custom":
                findings.append({
                    "type": "dead_rule",
                    "severity": "high",
                    "affected_rules": [r["rule_name"]],
                    "title": f"Dead rule: {r['rule_name']}",
                    "description": "Zero hits in the 30-day audit window.",
                    "recommendation": "Verify the rule still has a current use case; if not, remove.",
                    "confidence": 0.9,
                })
        # Add an fms_review for managed-rule-group context
        managed_names = [r["rule_name"] for r in rules if r["rule_kind"] == "managed"]
        if managed_names:
            findings.append({
                "type": "fms_review",
                "severity": "low",
                "affected_rules": managed_names[:2],
                "title": "AWS managed rule groups — verify coverage scope",
                "description": "Zero hits on a managed rule group is normal baseline; verify the ACL is in the request path.",
                "recommendation": "If hit volume seems too low, confirm the WAF is actually in front of the origin (DNS / CloudFront association check).",
                "confidence": 0.7,
            })
        if suspicious_requests:
            findings.append({
                "type": "bypass_candidate",
                "severity": "high",
                "affected_rules": [],
                "title": "Possible WAF bypass: shellshock reached origin",
                "description": (
                    "HTTP request containing shellshock payload "
                    "'() { :;}; /bin/bash -c ...' in User-Agent header was "
                    "served 200 OK. Sample URI: /."
                ),
                "recommendation": "Enable AWSManagedRulesKnownBadInputsRuleSet on the affected ACL.",
                "confidence": 0.95,
                "evidence": "log-sample",
            })
            findings.append({
                "type": "bypass_candidate",
                "severity": "high",
                "affected_rules": [],
                "title": "Possible WAF bypass: xss reached origin",
                "description": (
                    "URL-encoded XSS payload in `args` query string reached "
                    "the origin. Sample URI: /search."
                ),
                "recommendation": "Enable AWSManagedRulesCommonRuleSet in BLOCK (not Count) mode.",
                "confidence": 0.85,
                "evidence": "log-sample",
            })
        return {"rules": enriched, "findings": findings}

    audit_mod.ai_pipeline.run_pipeline = fake_run_pipeline

    audit_id = audit_mod.create_audit_run(
        db=db,
        account_id="371126261144",
        role_arn="arn:aws:iam::371126261144:role/ruleiq-audit",
        region="us-east-1",
        log_window_days=30,
        external_id="x" * 64,
    )
    audit_mod.run_audit_pipeline(audit_id, db)

    run = db["audit_runs"].find_one({"_id": audit_id})
    rules = list(db["rules"].find({"audit_run_id": audit_id}).sort("priority", 1))
    findings = list(db["findings"].find({"audit_run_id": audit_id}))

    print(f"Generated audit  : {audit_id}")
    print(f"  data_source    : {run['data_source']}")
    print(f"  rule_count     : {run['rule_count']}")
    print(f"  web_acls       : {[(a['name'], a['attached']) for a in run.get('web_acls', [])]}")
    print(f"  scopes         : {run.get('scopes')}")
    print(f"  suspicious     : {len(run.get('suspicious_request_sample', []))}")
    print(f"  debug_samples  : {len(run.get('debug_log_sample', []))}")
    print(f"  findings types : {sorted({f['type'] for f in findings})}")
    print(f"  modes seen     : {sorted({r['action'] for r in rules})}")

    pdf_bytes = render_audit_pdf(run, rules, findings)
    out_path = Path("/app/dist/sample-audit.pdf")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(pdf_bytes)
    print(f"Wrote {out_path} ({len(pdf_bytes)} bytes)")


if __name__ == "__main__":
    main()
