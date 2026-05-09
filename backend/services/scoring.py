"""Deterministic scoring helpers for findings + dollar-waste estimate.

All numbers here are intentionally transparent so a reviewer can audit the
math without reading code:

  severity_score (per finding, int 0..100):
      severity_weight = {"high":1.0, "medium":0.6, "low":0.3}[severity]
      breadth = min(1.0, len(affected_rules) / max(1, total_rule_count))
      score   = round(severity_weight * confidence * (0.6 + 0.4 * breadth) * 100)
      score   = clamp(score, 0, 100)

  estimated_waste_usd (per audit run, float):
      AWS WAFv2 us-east-1 public list pricing (snapshot 2026-02; revisit
      whenever AWS publishes a price change):
          WEB_ACL_MONTHLY_USD = $5.00
          RULE_MONTHLY_USD    = $1.00
          REQUEST_MILLION_USD = $0.60   # not used in Phase 1
      dead_rule_count = rules with hit_count == 0 AND fms_managed == False
      waste_usd       = dead_rule_count * RULE_MONTHLY_USD

  estimated_waste_breakdown (per audit run, list[dict]):
      One entry per dead non-FMS rule:
          {rule_name, monthly_usd: 1.00, reason}
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

WEB_ACL_MONTHLY_USD = 5.00
RULE_MONTHLY_USD = 1.00
REQUEST_MILLION_USD = 0.60  # reserved for Phase 2

SEVERITY_WEIGHT = {"high": 1.0, "medium": 0.6, "low": 0.3}


def severity_score(
    severity: str,
    confidence: float,
    affected_rules: List[str],
    total_rule_count: int,
) -> int:
    weight = SEVERITY_WEIGHT.get(severity, 0.0)
    breadth = min(1.0, len(affected_rules) / max(1, total_rule_count))
    raw = weight * float(confidence) * (0.6 + 0.4 * breadth) * 100
    return max(0, min(100, round(raw)))


def _is_dead_customer(rule: Dict[str, Any]) -> bool:
    return (rule.get("hit_count") or 0) == 0 and not rule.get("fms_managed", False)


def estimated_waste_usd(rules: Iterable[Dict[str, Any]]) -> float:
    dead_customer = [r for r in rules if _is_dead_customer(r)]
    return round(len(dead_customer) * RULE_MONTHLY_USD, 2)


def estimated_waste_breakdown(rules: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in rules:
        if _is_dead_customer(r):
            out.append(
                {
                    "rule_name": r["rule_name"],
                    "monthly_usd": RULE_MONTHLY_USD,
                    "reason": "Zero hits in 30 days; rule fee $1/month",
                }
            )
    return out
