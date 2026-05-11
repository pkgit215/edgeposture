"""Deterministic scoring helpers — Phase 5: kind-aware severity.

Severity table (per (rule_kind, hit_bucket) pair):

  Rule Kind          | Hits=0           | Hits<10/30d  | Hits Healthy
  -------------------+------------------+--------------+--------------
  custom             | HIGH (truly dead)| MEDIUM       | LOW
  managed            | LOW (info)       | LOW          | LOW
  rate_based         | MEDIUM (gap?)    | LOW          | LOW

Rule kinds are derived in aws_waf.classify_rule_kind() from the rule's
Statement shape; ingestion stamps `rule_kind` on every Rule document.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

WEB_ACL_MONTHLY_USD = 5.00
RULE_MONTHLY_USD = 1.00
REQUEST_MILLION_USD = 0.60

SEVERITY_WEIGHT = {"high": 1.0, "medium": 0.6, "low": 0.3}

LOW_HIT_THRESHOLD = 10  # < this many hits in window → "low" bucket


def _hit_bucket(hit_count: int) -> str:
    if hit_count == 0:
        return "zero"
    if hit_count < LOW_HIT_THRESHOLD:
        return "low"
    return "healthy"


def kind_severity(rule_kind: str, hit_count: int) -> Tuple[str, int]:
    """Return (severity_label, base_score) for a rule given its kind+hits.

    The base_score is the *pre*-breadth/confidence score; finding-level
    severity_score() multiplies by confidence and breadth as before.
    """
    bucket = _hit_bucket(hit_count)
    table = {
        ("custom",     "zero"):    ("high",   85),
        ("custom",     "low"):     ("medium", 55),
        ("custom",     "healthy"): ("low",    20),
        ("managed",    "zero"):    ("low",    20),  # was HIGH 63 → noise
        ("managed",    "low"):     ("low",    20),
        ("managed",    "healthy"): ("low",    15),
        ("rate_based", "zero"):    ("medium", 50),
        ("rate_based", "low"):     ("low",    25),
        ("rate_based", "healthy"): ("low",    15),
    }
    return table.get((rule_kind, bucket), ("low", 20))


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
    """A 'truly dead' customer rule for waste-USD accounting.

    Managed rule groups with zero hits are NOT waste — they're defensive
    signature lists that fire only when matching traffic appears. Excluding
    them is the Phase 5 fix.
    """
    if rule.get("fms_managed", False):
        return False
    if (rule.get("rule_kind") or "custom") == "managed":
        return False
    return (rule.get("hit_count") or 0) == 0


def estimated_waste_usd(rules: Iterable[Dict[str, Any]]) -> float:
    return round(
        sum(RULE_MONTHLY_USD for r in rules if _is_dead_customer(r)), 2
    )


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
