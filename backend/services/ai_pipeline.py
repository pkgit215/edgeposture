"""Two-pass AI pipeline for RuleIQ Phase 0.

Pass 1 — Rule Explainer: per-rule plain-English explanation.
Pass 2 — Findings Generator: list of audit findings across all rules.

OpenAI calls are wrapped with a tenacity retry policy.
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
    "CONSISTENCY REQUIREMENT: every rule with hit_count==0 AND fms_managed==false "
    "MUST be classified into exactly one of: `dead_rule` (default for any rule "
    "that was clearly designed to fire, e.g. block patterns or known-bad "
    "headers), `bypass_candidate` (only when there is positive evidence a "
    "bypass is plausible), or `quick_win` (only when redundant with another "
    "rule). Do not silently omit such rules. If the rule's purpose is unclear, "
    "default to `dead_rule`."
)

_client_singleton: Optional[OpenAI] = None


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


def explain_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Pass 1: produce {explanation, working, concerns} for a single rule."""
    user = json.dumps(
        {
            "rule_name": rule.get("rule_name"),
            "web_acl_name": rule.get("web_acl_name"),
            "priority": rule.get("priority"),
            "action": rule.get("action"),
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
    return _chat_json(PASS1_SYSTEM, user)


def generate_findings(rules_with_explanations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pass 2: produce a list of findings given the enriched rule list."""
    payload = json.dumps({"rules": rules_with_explanations})
    parsed = _chat_json(PASS2_SYSTEM, payload)
    findings = parsed.get("findings", [])
    if not isinstance(findings, list):
        return []
    return findings


def run_pipeline(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run Pass 1 over every rule, then Pass 2.

    Returns a dict shaped {"rules": [...with ai_explanation...], "findings": [...]}.
    """
    enriched: List[Dict[str, Any]] = []
    for rule in rules:
        explanation = explain_rule(rule)
        enriched_rule = {**rule, "ai_explanation": explanation}
        enriched.append(enriched_rule)

    findings = generate_findings(enriched)
    return {"rules": enriched, "findings": findings}
