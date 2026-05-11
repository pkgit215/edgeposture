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
    # Phase 5.3.2 — `quick_win_unused` sub-variant: a SINGLE custom rule
    # that has no current traffic match and no duplicate pair (this is
    # the BlockOldCurlScanners-style finding).
    "quick_win_unused": {
        "suggested_actions": [
            (
                "Verify with the rule's original author whether the "
                "protection is still needed. If obsolete, delete the rule "
                "to reduce console clutter and audit surface area."
            ),
        ],
        "verify_by": (
            "After deletion: confirm the rule is removed via "
            "`aws wafv2 get-web-acl` and that the next 30-day audit no "
            "longer flags it."
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
    elif ftype == "quick_win":
        # Phase 5.3.2 — `quick_win` with no shared_resource/stranded
        # evidence is the single-unused-custom-rule variant (e.g.
        # BlockOldCurlScanners). Different copy.
        ftype = "quick_win_unused"
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



# Phase 5.3.2 — `impact` field. One short paragraph per finding type
# explaining the business / security consequence in plain English.
# Copy is user-approved — do NOT paraphrase.
_IMPACT_COPY: Dict[str, str] = {
    "bypass_candidate": (
        "Attack-shaped traffic is reaching your origin uninspected. If "
        "the payload is genuinely malicious, your WAF is providing no "
        "defense against this signature class. Direct relevance to "
        "SOC 2 CC6.6, PCI-DSS 6.6, ISO 27001 A.13.1.2."
    ),
    "dead_rule_custom": (
        "If this rule was intended to be active, the traffic it was "
        "supposed to block is no longer being inspected. If obsolete, "
        "it's creating noise that slows incident response and inflates "
        "your rule-count quota."
    ),
    "dead_rule_managed": (
        "Either traffic isn't reaching this rule group (routing problem) "
        "or the rule group doesn't match your traffic patterns "
        "(configuration problem). Either way, the protection you're "
        "paying for isn't engaging."
    ),
    "orphaned_web_acl": (
        "Pure operational waste — fixed monthly fee with zero traffic "
        "served. Also creates audit confusion: reviewers see an "
        "attached-looking Web ACL that does nothing."
    ),
    "count_mode_with_hits": (
        "Rule appears active in the AWS console but is logging instead "
        "of blocking. Attacks matching this signature are being recorded, "
        "not stopped. Common cause: rule was deployed in COUNT for "
        "evaluation and never promoted."
    ),
    "count_mode_high_volume": (
        "Rule appears active in the AWS console but is logging instead "
        "of blocking. Attacks matching this signature are being recorded, "
        "not stopped. Common cause: rule was deployed in COUNT for "
        "evaluation and never promoted."
    ),
    "count_mode_long_duration": (
        "Rule appears active in the AWS console but is logging instead "
        "of blocking. Attacks matching this signature are being recorded, "
        "not stopped. Common cause: rule was deployed in COUNT for "
        "evaluation and never promoted."
    ),
    "conflict": (
        "Two rules with overlapping or identical match conditions create "
        "unpredictable evaluation order, and one is effectively dead "
        "code. Cleanup reduces noise in your audit and speeds future "
        "incident response."
    ),
    "rule_conflict": (
        "Two rules with overlapping or identical match conditions create "
        "unpredictable evaluation order, and one is effectively dead "
        "code. Cleanup reduces noise in your audit and speeds future "
        "incident response."
    ),
    "fms_review": (
        "You cannot fix this directly — the rule is controlled by "
        "another team via Firewall Manager. But it appears in your audit "
        "report and must either be escalated or formally accepted as "
        "out-of-scope."
    ),
    "quick_win": (
        "Low-risk rule cleanup. Reduces console clutter, improves "
        "onboarding for new engineers, and shrinks your security review "
        "surface area."
    ),
    "quick_win_unused": (
        "Low-risk rule cleanup. Reduces console clutter, improves "
        "onboarding for new engineers, and shrinks your security review "
        "surface area."
    ),
    "stranded_rule": (
        "A rule duplicate exists on an orphaned Web ACL that protects "
        "nothing. The duplicate is dead code — it consumes audit "
        "attention and adds to your rule-count quota without providing "
        "any defense. Cleanup is mechanical: either delete the orphan "
        "ACL or remove the redundant rule from it."
    ),
    "managed_rule_override_count": (
        "A managed rule inside this group has been overridden to COUNT. "
        "The override is invisible at the group level, but the specific "
        "protection is logging, not blocking."
    ),
}


def impact_for(
    finding: Dict[str, Any],
    rules_by_name: Optional[Dict[str, Dict[str, Any]]] = None,
) -> str:
    """Phase 5.3.2 — return the canonical Impact copy for this finding.

    `dead_rule` dispatches on managed vs custom (same dispatch as
    remediation_for). `quick_win` with `evidence='stranded'` maps to the
    `stranded_rule` copy. Unknown types fall through to an empty string
    (the PDF / UI renderer treats empty as 'omit the section').
    """
    ftype = finding.get("type") or ""
    evidence = finding.get("evidence")
    if ftype == "quick_win" and evidence == "stranded":
        key = "stranded_rule"
    elif ftype == "quick_win" and evidence == "shared_resource":
        key = "quick_win"
    elif ftype == "quick_win":
        key = "quick_win_unused"
    elif ftype == "dead_rule":
        kind = _affected_kind_hint(
            list(finding.get("affected_rules") or []), rules_by_name
        )
        key = "dead_rule_managed" if kind == "managed" else "dead_rule_custom"
    else:
        key = ftype
    return _IMPACT_COPY.get(key, "")
