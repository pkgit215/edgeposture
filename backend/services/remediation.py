"""Phase 5.3 — Canned remediation guidance per finding type.

Less AI variance, more trust. Every finding gets a 4-field block:
    suggested_actions: List[str]   (1–3 concrete steps)
    verify_by:         str         (how to confirm the fix worked)
    disclaimer:        str         (universal copy)

For `dead_rule` we further key on whether the affected rules are
custom or managed-group rules (different guidance, different verifier).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

UNIVERSAL_DISCLAIMER = (
    "RuleIQ does not generate WAF rules. Recommendations point to "
    "AWS-maintained managed groups and high-level configuration changes. "
    "Deploy new rules in COUNT mode for 7+ days before promoting to BLOCK "
    "to assess false-positive risk. Test in non-production WAFs when "
    "possible. Rollback plan: detach the new rule group via the WAF console."
)


# Lookup keyed by `(finding_type, kind?)`. `kind` is optional and used to
# disambiguate `dead_rule` (managed vs custom).
_TABLE: Dict[str, Dict[str, Any]] = {
    "bypass_candidate": {
        "suggested_actions": [
            (
                "Enable a managed rule group that covers this signature "
                "class. For shellshock / CVE patterns: "
                "AWSManagedRulesUnixRuleSet or "
                "AWSManagedRulesKnownBadInputsRuleSet. For SQLi gaps: "
                "AWSManagedRulesSQLiRuleSet. For XSS / Common: "
                "AWSManagedRulesCommonRuleSet."
            ),
            (
                "Deploy the chosen group in COUNT mode first; review the "
                "false-positive sample over 7 days; promote to BLOCK only "
                "after vetting."
            ),
        ],
        "verify_by": (
            "Replay a captured suspicious request from the audit's "
            "`suspicious_request_sample` against the WAF after rollout — "
            "it should return 403."
        ),
    },
    "dead_rule_custom": {
        "suggested_actions": [
            (
                "Review with the original author / team. If the rule's "
                "purpose is no longer relevant, delete it."
            ),
            (
                "If the purpose is current but the rule isn't matching, "
                "audit the rule's statement against current traffic "
                "patterns — usually a field-name or encoding mismatch."
            ),
        ],
        "verify_by": (
            "Confirm the rule's hit count over the next 30 days remains "
            "zero; OR if you intend it to fire, generate synthetic test "
            "traffic matching its statement and verify a hit."
        ),
    },
    "dead_rule_managed": {
        "suggested_actions": [
            (
                "Zero hits on a managed defensive group is often expected "
                "(no matching threats observed). Investigate only if the "
                "WAF is mis-placed (traffic bypassing it entirely) or if "
                "you have a specific compliance requirement to test "
                "coverage."
            ),
        ],
        "verify_by": (
            "Confirm the WAF is on the request path: `curl -sI "
            "https://your-app/<sensitive-path>` should hit your WAF, "
            "visible in CloudWatch log volume."
        ),
    },
    "orphaned_web_acl": {
        "suggested_actions": [
            (
                "Either attach the ACL to a resource that needs "
                "protection, or delete it to stop the $5/mo fixed fee."
            ),
            (
                "If recently detached during migration, confirm the "
                "intended target was reattached."
            ),
        ],
        "verify_by": (
            "After deletion: `aws wafv2 list-web-acls --scope <scope>` "
            "should not list it. After re-attachment: `aws wafv2 "
            "list-resources-for-web-acl --web-acl-arn <arn>` returns the "
            "new resource."
        ),
    },
    "stranded_rule": {
        "suggested_actions": [
            (
                "Remove the duplicate rule from the orphaned ACL — it is "
                "protecting nothing."
            ),
            (
                "OR restore the orphan's intended resource attachment if "
                "the orphaning was unintentional."
            ),
        ],
        "verify_by": (
            "After cleanup: re-run a RuleIQ audit and confirm the "
            "stranded finding is gone."
        ),
    },
    "rule_conflict": {
        "suggested_actions": [
            (
                "Consolidate into one ACL on the resource. Conflicting "
                "priorities can produce unpredictable behavior."
            ),
            (
                "Verify rule statements are identical before merging — "
                "subtle differences (text transformations, field-to-match) "
                "are why duplicates were created in the first place."
            ),
        ],
        "verify_by": (
            "After consolidation: re-run a RuleIQ audit and confirm no "
            "duplicate finding is produced for this rule pair."
        ),
    },
    "quick_win": {
        "suggested_actions": [
            (
                "Review the redundancy in the rule pair and remove the "
                "weaker / less-specific copy."
            ),
        ],
        "verify_by": (
            "After cleanup: re-run a RuleIQ audit and confirm the "
            "duplicate finding is gone, and the remaining rule's hit "
            "count includes the merged traffic."
        ),
    },
    "count_mode_with_hits": {
        "suggested_actions": [
            (
                "Review whether the rule is sufficiently mature to "
                "promote from COUNT to BLOCK."
            ),
            (
                "Sample the COUNT hits — if all match the intended "
                "signature, promote. If you see legitimate-looking "
                "matches, refine the statement first."
            ),
        ],
        "verify_by": (
            "After promotion: the rule's hit_count should redistribute "
            "(originally-COUNT hits become BLOCKs). Monitor for 7 days "
            "for unexpected blocks before considering the change stable."
        ),
    },
    "count_mode_high_volume": {
        "suggested_actions": [
            (
                "High sustained COUNT volume strongly suggests the rule "
                "is mature. Schedule a promote-to-BLOCK window."
            ),
            (
                "Snapshot a 200-event sample first; have an engineer "
                "spot-check for unexpected matches before flipping."
            ),
        ],
        "verify_by": (
            "After promotion: monitor 403 rates and customer error "
            "reports for 48 hours. Roll back if false-positives spike."
        ),
    },
    "count_mode_long_duration": {
        "suggested_actions": [
            (
                "A rule that has accumulated significant COUNT hits over "
                "time is likely safe to promote — the COUNT state appears "
                "forgotten."
            ),
            (
                "Re-confirm intent with the rule's owning team before "
                "promotion."
            ),
        ],
        "verify_by": (
            "After promotion: hit_count should remain steady, with "
            "matches now reflected as BLOCKs in CloudWatch metrics."
        ),
    },
    "managed_rule_override_count": {
        "suggested_actions": [
            (
                "Review whether the sub-rule override to COUNT is still "
                "intentional. Common reason: an early false-positive that "
                "has since been addressed by upstream signature updates."
            ),
            (
                "If no current rationale, remove the override so the "
                "managed group's default action applies."
            ),
        ],
        "verify_by": (
            "After removal: the managed group's default action applies. "
            "Monitor hit volumes for 7 days for unexpected blocks."
        ),
    },
    "fms_review": {
        "suggested_actions": [
            (
                "Flag to the central security / Firewall Manager admin "
                "team. The rule is controlled by a delegated admin "
                "account and cannot be modified locally."
            ),
        ],
        "verify_by": (
            "The FMS admin team confirms either intent or remediation "
            "for the central policy."
        ),
    },
}


def _affected_kind_hint(
    affected_rules: List[str],
    rules_by_name: Optional[Dict[str, Dict[str, Any]]] = None,
) -> str:
    """Return 'managed' iff every affected rule is a managed-group rule;
    otherwise 'custom'. Used to pick the right `dead_rule_*` variant."""
    if not rules_by_name or not affected_rules:
        return "custom"
    kinds = set()
    for n in affected_rules:
        r = rules_by_name.get(n)
        if not r:
            return "custom"
        kinds.add((r.get("rule_kind") or "custom"))
        if r.get("fms_managed"):
            kinds.add("managed")
    return "managed" if kinds == {"managed"} else "custom"


def remediation_for(
    finding: Dict[str, Any],
    rules_by_name: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Return the remediation dict for a single finding.

    Output shape:
        {
            "suggested_actions": [...],
            "verify_by": "...",
            "disclaimer": "...",
        }

    Unknown finding types fall through to a generic remediation that
    still carries the universal disclaimer.
    """
    ftype = finding.get("type") or ""
    # Special handling for stranded_rule (currently emitted as type='quick_win'
    # with evidence='stranded' — keep both keys lookupable).
    evidence = finding.get("evidence")
    if ftype == "quick_win" and evidence == "stranded":
        ftype = "stranded_rule"
    elif ftype == "quick_win" and evidence == "shared_resource":
        ftype = "quick_win"  # generic quick_win remediation
    elif ftype == "conflict":
        ftype = "rule_conflict"

    if ftype == "dead_rule":
        kind = _affected_kind_hint(
            list(finding.get("affected_rules") or []), rules_by_name
        )
        key = "dead_rule_managed" if kind == "managed" else "dead_rule_custom"
    else:
        key = ftype

    entry = _TABLE.get(key)
    if not entry:
        entry = {
            "suggested_actions": [
                "Review the finding with the team that owns the affected rules."
            ],
            "verify_by": (
                "Re-run a RuleIQ audit after taking action; the finding "
                "should disappear or downgrade."
            ),
        }
    return {
        "suggested_actions": list(entry["suggested_actions"]),
        "verify_by": entry["verify_by"],
        "disclaimer": UNIVERSAL_DISCLAIMER,
    }
