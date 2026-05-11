"""Two/three-pass AI pipeline for RuleIQ.

Pass 1 — Rule Explainer:        per-rule plain-English explanation. Domain-
                                  aware context for AWS managed rule groups
                                  is prepended to the user message so the
                                  model never recommends "test with synthetic
                                  traffic" against an IP reputation list.
Pass 2 — Findings Generator:    full audit findings across all rules.
                                  Suppresses dead_rule/quick_win for FMS-
                                  managed rules (model-side guardrail) and
                                  the audit pipeline applies a second-layer
                                  filter for orphaned Web ACLs.
Pass 3 — Bypass Detection:      analyses real request samples (top 50 most
                                  attack-shaped 2xx/3xx requests that
                                  REACHED the origin) and produces
                                  `bypass_candidate` findings with
                                  `evidence='log-sample'`.

OpenAI calls are wrapped with tenacity (4 attempts, exp backoff, retry on
RateLimitError + APIError).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from openai import APIError, OpenAI, RateLimitError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .secrets import get_openai_key

logger = logging.getLogger(__name__)

MODEL = "gpt-4o"

# Module-level OpenAI client singleton — lazy-built on first call.
_client_singleton: Optional[OpenAI] = None

PASS1_SYSTEM = (
    "You are an AWS WAF security expert. Given a WAF rule definition and its "
    "traffic statistics, explain in 2-3 plain English sentences what this rule "
    "is designed to block, whether it appears to be working based on the data, "
    "and any concerns. Return JSON with fields: explanation (string), working "
    "(boolean), concerns (string or null). "
    "When generating the `working` boolean: set false if `hit_count==0` and "
    "the rule's design implies it should be firing (block patterns, IP blocks, "
    "header matches). Only set true for 0-hit rules that are intentionally "
    "passive (e.g. rate-based rules below threshold)."
)

PASS2_SYSTEM = (
    "You are an AWS WAF security auditor. Given a list of WAF rules with their "
    "statistics and explanations, identify: (1) dead rules — rules with zero "
    "hits in 30 days that should be firing, (2) potential bypasses — rules "
    "with unexpectedly low hit rates given their purpose, (3) rule conflicts "
    "— rules that contradict or overlap each other, (4) quick wins — rules "
    "safe to remove or consolidate, (5) FMS review items — FMS-managed rules "
    "with concerns. Return JSON with key 'findings' as an array. Each finding "
    "has: type (dead_rule | bypass_candidate | conflict | quick_win | "
    "fms_review), severity (high | medium | low), affected_rules (array of "
    "rule names), title (string), description (string), recommendation "
    "(string), confidence (0.0-1.0).\n\n"
    "**CRITICAL FMS RULES**: FMS-managed rules cannot be modified by the "
    "customer. NEVER produce a `dead_rule` or `quick_win` finding that lists "
    "an FMS-managed rule in `affected_rules`. For FMS-managed rules with zero "
    "hits or concerns, use `type='fms_review'`, `severity='low'`, and "
    "recommendation copy stating the rule is controlled by a delegated admin "
    "account and should be flagged for review with the central security team."
    "\n\n"
    "**CRITICAL MANAGED RULE GROUPS**: AWS managed rule groups "
    "(rule_kind='managed') are defensive signature lists. Zero hits on these "
    "is the *normal* baseline — not waste. Use severity='low' and prefer "
    "type='fms_review' framing ('verify coverage scope') over 'dead_rule'.\n\n"
    "CONSISTENCY REQUIREMENT: every rule with hit_count==0 AND fms_managed==false "
    "AND rule_kind=='custom' MUST be classified into exactly one of: "
    "`dead_rule` (default for any rule that was clearly designed to fire, "
    "e.g. block patterns or known-bad headers), `bypass_candidate` (only "
    "when there is positive evidence a bypass is plausible), or `quick_win` "
    "(only when redundant with another rule). Do not silently omit such "
    "rules. If the rule's purpose is unclear, default to `dead_rule`."
)

# Phase 5.6 — domain-aware context for known AWS managed rule groups.
# Pre-pended to the Pass-1 user message when the rule's `rule_name` or
# its `ManagedRuleGroupStatement.Name` matches.
MANAGED_RULE_CONTEXT: Dict[str, str] = {
    "AWSManagedRulesAmazonIpReputationList": (
        "AWS-maintained list of IPs flagged via Amazon's threat intel. Zero "
        "hits is normal — fires only when traffic arrives from currently-"
        "flagged IPs. Do not recommend 'testing with synthetic traffic' — "
        "the operator cannot synthesize known-bad-IP traffic from their own "
        "infrastructure. Recommend coverage-scope review instead."
    ),
    "AWSManagedRulesAnonymousIpList": (
        "Tor exits, public hosting providers, anonymizers. Zero hits means "
        "no anonymized traffic — common for B2B apps with known user "
        "populations. Not waste; informational at most."
    ),
    "AWSManagedRulesCommonRuleSet": (
        "OWASP Top 10 baseline. Zero hits is unusual for any internet-facing "
        "app — investigate whether the origin is correctly behind the WAF, "
        "or whether legitimate scanner/bot traffic is being routed elsewhere."
    ),
    "AWSManagedRulesKnownBadInputsRuleSet": (
        "Generic CVE / exploit signatures (log4shell, etc.). Low hits is "
        "normal in well-maintained environments; zero hits warrants a quick "
        "check that the WAF is actually in the request path."
    ),
    "AWSManagedRulesSQLiRuleSet": (
        "SQL injection signatures. Low hits typical for APIs without "
        "open query parameters; zero hits warrants WAF-path verification."
    ),
    "AWSManagedRulesLinuxRuleSet": (
        "Linux-specific exploit patterns. Zero hits normal for Windows/.NET "
        "origins or static-content workloads."
    ),
    "AWSManagedRulesUnixRuleSet": (
        "Generic Unix command-injection signatures. Zero hits normal in "
        "modern containerised stacks; informational only."
    ),
    "AWSManagedRulesPHPRuleSet": (
        "PHP-specific exploit signatures. Zero hits expected unless the "
        "origin actually runs PHP — informational."
    ),
    "AWSManagedRulesWordPressRuleSet": (
        "WordPress-specific exploit signatures. Zero hits expected unless "
        "the origin runs WordPress — informational."
    ),
    "AWSManagedRulesBotControlRuleSet": (
        "Paid bot-control group. Different cost calculus — zero hits could "
        "indicate genuine absence of automated traffic OR that the group is "
        "configured in monitor-only mode. Review CloudWatch metrics, not "
        "just rule terminations."
    ),
    "AWSManagedRulesATPRuleSet": (
        "Paid account-takeover-prevention group. Hits only fire on auth "
        "endpoints with credential-stuffing-shaped traffic; zero hits common "
        "for B2B apps with low credential-stuffing exposure."
    ),
    "AWSManagedRulesACFPRuleSet": (
        "Paid account-creation-fraud-prevention group. Similar to ATP — "
        "zero hits common in low-fraud-exposure workloads."
    ),
}

PASS3_SYSTEM = (
    "You are an AWS WAF security expert. Given a list of HTTP requests that "
    "reached the origin (status 2xx/3xx) but contain attack-shaped patterns, "
    "identify which represent ACTUAL WAF coverage gaps versus benign matches "
    "(e.g. legitimate use of /admin/ by an authenticated admin, security "
    "research traffic from internal teams, etc.). Return JSON with key "
    "'gaps' as an array. For each true gap, include: pattern_type (one of: "
    "shellshock, log4shell, sqli, xss, lfi, rfi, path_traversal, "
    "command_injection, scanner, other), severity (high|medium|low), "
    "example_uri (one representative URI), recommendation (a specific AWS "
    "managed rule group or custom rule that would close the gap), "
    "confidence (0.0-1.0)."
)


def get_openai_client() -> OpenAI:
    """Lazy OpenAI client, cached at module level."""
    global _client_singleton
    if _client_singleton is None:
        _client_singleton = OpenAI(api_key=get_openai_key())
    return _client_singleton


@retry(
    reraise=True,
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception_type((RateLimitError, APIError)),
)
def _chat_json(system: str, user: str) -> Dict[str, Any]:
    """Call OpenAI chat completions with JSON response format."""
    client = get_openai_client()
    resp = client.chat.completions.create(
        model=MODEL,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    content = resp.choices[0].message.content or "{}"
    return json.loads(content)


def _extract_managed_group_name(rule: Dict[str, Any]) -> Optional[str]:
    """Return the AWS managed rule group `Name` if the rule wraps one.

    Inspection order:
      1. statement_json.ManagedRuleGroupStatement.Name
      2. rule_name itself (FMS often prefixes managed group rules with
         "FMS-<GroupName>", strip that)
    """
    stmt = rule.get("statement_json") or {}
    if isinstance(stmt, dict):
        mrg = stmt.get("ManagedRuleGroupStatement")
        if isinstance(mrg, dict):
            name = mrg.get("Name")
            if isinstance(name, str) and name in MANAGED_RULE_CONTEXT:
                return name
    name = rule.get("rule_name") or ""
    if isinstance(name, str):
        stripped = name.removeprefix("FMS-")
        if stripped in MANAGED_RULE_CONTEXT:
            return stripped
        if name in MANAGED_RULE_CONTEXT:
            return name
    return None


def explain_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Pass 1: produce {explanation, working, concerns} for a single rule."""
    user = json.dumps(
        {
            "rule_name": rule.get("rule_name"),
            "web_acl_name": rule.get("web_acl_name"),
            "priority": rule.get("priority"),
            "action": rule.get("action"),
            "rule_kind": rule.get("rule_kind"),
            "statement_json": rule.get("statement_json"),
            "hit_count": rule.get("hit_count"),
            "last_fired": rule.get("last_fired"),
            "count_mode_hits": rule.get("count_mode_hits"),
            "sample_uris": rule.get("sample_uris"),
            "fms_managed": rule.get("fms_managed"),
            "override_action": rule.get("override_action"),
        }
    )
    if rule.get("fms_managed"):
        user += (
            "\n\nNOTE: This rule is FMS-managed (controlled by AWS Firewall "
            "Manager from a delegated admin account). The customer cannot "
            "modify it directly."
        )
    group_name = _extract_managed_group_name(rule)
    if group_name:
        user += (
            f"\n\nDOMAIN CONTEXT for managed rule group {group_name}: "
            f"{MANAGED_RULE_CONTEXT[group_name]}"
        )
    return _chat_json(PASS1_SYSTEM, user)


def generate_findings(rules_with_explanations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pass 2: produce a list of findings given the enriched rule list."""
    payload = json.dumps({"rules": rules_with_explanations})
    parsed = _chat_json(PASS2_SYSTEM, payload)
    findings = parsed.get("findings", [])
    if not isinstance(findings, list):
        return []
    return findings


def detect_bypasses(
    suspicious_requests: List[Dict[str, Any]],
    web_acl_names_fallback: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Pass 3: produce `bypass_candidate` findings from real request logs.

    `suspicious_requests` MUST already be pre-filtered to:
      * responseCodeSent in 2xx/3xx (the request REACHED the origin), AND
      * top-N by `aws_waf.score_request_suspicion(req)`.

    Phase 5.3.2 — each emitted bypass finding now has a NON-EMPTY
    `affected_rules` populated from `_web_acl_name` tagged onto each
    suspicious request by the audit pipeline. If tagging is missing
    (legacy code path), falls back to `web_acl_names_fallback`.
    The function asserts the invariant — tests will fail loud if a
    bypass finding ever leaks out with empty `affected_rules`.

    Returns a list of finding dicts shaped exactly like Pass-2 findings,
    each tagged `evidence='log-sample'` so the audit-run merge step can
    persist the provenance flag onto the Mongo document.
    """
    if not suspicious_requests:
        return []
    # Collect every distinct Web ACL the suspicious-request sample
    # came from. Used both for emission and for the affected_rules
    # invariant assertion.
    acl_names: List[str] = []
    seen = set()
    for req in suspicious_requests:
        v = (req or {}).get("_web_acl_name")
        if isinstance(v, str) and v and v not in seen:
            acl_names.append(v); seen.add(v)
    if not acl_names and web_acl_names_fallback:
        for n in web_acl_names_fallback:
            if isinstance(n, str) and n and n not in seen:
                acl_names.append(n); seen.add(n)

    payload = json.dumps({
        "requests": [{k: v for k, v in (r or {}).items() if not k.startswith("_")}
                     for r in suspicious_requests[:50]]
    })
    parsed = _chat_json(PASS3_SYSTEM, payload)
    gaps = parsed.get("gaps", [])
    if not isinstance(gaps, list):
        return []
    out: List[Dict[str, Any]] = []
    for g in gaps:
        if not isinstance(g, dict):
            continue
        pattern = str(g.get("pattern_type") or "other")
        severity = str(g.get("severity") or "low")
        if severity not in ("high", "medium", "low"):
            severity = "low"
        example = g.get("example_uri") or ""
        rec = g.get("recommendation") or (
            "Consider AWSManagedRulesKnownBadInputsRuleSet or a custom "
            "ByteMatch rule for this pattern."
        )
        try:
            confidence = float(g.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        # Phase 5.3.2 — affected_rules invariant.
        affected = list(acl_names)
        assert affected, (
            f"detect_bypasses must never emit a finding with empty "
            f"affected_rules. pattern={pattern!r} sample_size="
            f"{len(suspicious_requests)} fallback="
            f"{web_acl_names_fallback!r}"
        )
        out.append(
            {
                "type": "bypass_candidate",
                "severity": severity,
                "title": f"Possible WAF bypass: {pattern} reached origin",
                "description": (
                    f"Request matching pattern '{pattern}' was answered 2xx/3xx "
                    f"by the origin. Example: {example}"
                ),
                "recommendation": rec,
                "affected_rules": affected,
                "confidence": confidence,
                "evidence": "log-sample",
            }
        )
    return out


def run_pipeline(
    rules: List[Dict[str, Any]],
    suspicious_requests: Optional[List[Dict[str, Any]]] = None,
    web_acl_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run Pass 1 over every rule, Pass 2 over enriched list, optional Pass 3
    over suspicious request samples.

    Phase 5.3.2 — `web_acl_names` is passed through to `detect_bypasses`
    as a fallback for the `affected_rules` invariant when the suspicious
    requests weren't pre-tagged by the audit pipeline.

    Returns:
        {"rules": [...with ai_explanation...], "findings": [...]}.
    """
    enriched: List[Dict[str, Any]] = []
    for rule in rules:
        explanation = explain_rule(rule)
        enriched.append({**rule, "ai_explanation": explanation})

    findings: List[Dict[str, Any]] = list(generate_findings(enriched))
    if suspicious_requests:
        try:
            findings.extend(detect_bypasses(
                suspicious_requests,
                web_acl_names_fallback=web_acl_names,
            ))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Pass-3 bypass detection failed: %s", exc)
    return {"rules": enriched, "findings": findings}
