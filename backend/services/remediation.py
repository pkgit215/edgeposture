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



# ---------------------------------------------------------------------------
# Feat #2 — Flavor B (smart, account-aware) remediation.
# ---------------------------------------------------------------------------
# We add a second layer ON TOP of the canned table above. The canned copy
# is the universal fallback. The smart layer kicks in only for the four
# highest-value finding types and only when the caller can supply enough
# context (web_acls + rules_by_acl + suspicious sample).
#
# Output shape (when not None):
#     {
#         "suggested_actions": [str, ...],   # rewritten; overwrites canned
#         "evidence_samples":  [str, ...],   # 0–3 sample URIs (bypass only)
#     }
# `verify_by`, `disclaimer`, `impact` are NOT touched by this layer.

import re as _re  # noqa: E402  (intentional — extension lives at file end)


_SIG_TO_GROUP: Dict[str, str] = {
    "shellshock": "AWSManagedRulesUnixRuleSet",
    "log4shell":  "AWSManagedRulesKnownBadInputsRuleSet",
    "sqli":       "AWSManagedRulesSQLiRuleSet",
    "xss":        "AWSManagedRulesCommonRuleSet",
    "unix_cve":   "AWSManagedRulesUnixRuleSet",
    "bot":        "AWSManagedRulesBotControlRuleSet",
}

_ORPHAN_TITLE_RE = _re.compile(r"Web ACL '([^']+)' is")


def _next_priority_slot(acl_rules: List[Dict[str, Any]]) -> int:
    """Smallest gap >=10 in the rule-priority sequence, else max+10."""
    priorities = sorted(
        int(r.get("priority") or 0) for r in acl_rules
        if r.get("priority") is not None
    )
    if not priorities:
        return 10
    # First gap of at least 1 between consecutive priorities.
    for prev, nxt in zip(priorities, priorities[1:]):
        if nxt - prev >= 2:
            return prev + 1
    return priorities[-1] + 10


def _has_count_override(rule: Dict[str, Any]) -> bool:
    """True iff this rule (typically a managed group attachment) has a
    sub-rule override that demotes it to COUNT."""
    for ov in rule.get("managed_rule_overrides") or []:
        if str(ov.get("action") or "").upper() == "COUNT":
            return True
    return False


def _suspicious_for_sig(
    suspicious_sample: List[Dict[str, Any]],
    sig: str,
) -> List[Dict[str, Any]]:
    """Subset of suspicious requests whose `_signature_classes` includes
    the given class. Tolerant of the field being missing — older audit
    runs may have stored only `_suspicion_score`."""
    out: List[Dict[str, Any]] = []
    for r in suspicious_sample or []:
        classes = r.get("_signature_classes") or []
        if sig in classes:
            out.append(r)
    return out


def _evidence_uris(suspicious: List[Dict[str, Any]], limit: int = 3) -> List[str]:
    """Up to `limit` sample URIs (with query string) from a list of
    suspicious requests. Keeps them readable in the PDF — we don't decode
    URL-encoding here on purpose so reviewers see what actually hit the
    origin."""
    uris: List[str] = []
    for r in suspicious[:limit]:
        req = r.get("httpRequest") or {}
        uri = req.get("uri") or ""
        args = req.get("args") or ""
        full = f"{uri}?{args}" if args else uri
        if full and full not in uris:
            uris.append(full)
    return uris


def _smart_bypass(
    finding: Dict[str, Any],
    rules_by_acl: Dict[str, List[Dict[str, Any]]],
    suspicious_sample: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    sig = finding.get("signature_class")
    target_group = _SIG_TO_GROUP.get(sig or "")
    if not target_group:
        return None  # unknown signature class — fall back to canned
    affected = finding.get("affected_rules") or []
    if not affected:
        return None
    acl_name = affected[0]
    acl_rules = rules_by_acl.get(acl_name) or []
    matching = _suspicious_for_sig(suspicious_sample, sig)
    n_observed = len(matching)

    # Existing managed-group attachment (if any) with this VendorName/Name.
    existing = None
    for r in acl_rules:
        if (r.get("rule_kind") or "") != "managed":
            continue
        if r.get("rule_name") == target_group:
            existing = r
            break

    if existing is None:
        slot = _next_priority_slot(acl_rules)
        n_text = (
            f"{n_observed} attack-shaped request"
            f"{'s' if n_observed != 1 else ''} matched this signature class "
            "in the last 30 days. "
        ) if n_observed else ""
        action = (
            f"Add {target_group} at priority {slot} to {acl_name}. "
            f"{n_text}"
            f"Console: WAFv2 → Web ACLs → {acl_name} → Rules → "
            f"Add managed rule group → {target_group} → set priority {slot} → "
            f"Save."
        )
    elif (str(existing.get("action") or "").upper() == "COUNT"
          or _has_count_override(existing)):
        action = (
            f"{target_group} is present on {acl_name} but in COUNT mode. "
            f"Promote to BLOCK after a 7-day false-positive review. "
            f"Console: WAFv2 → Web ACLs → {acl_name} → Rules → "
            f"Edit {target_group} → Override action to none / BLOCK → Save."
        )
    else:
        prio = existing.get("priority")
        action = (
            f"Investigate why {target_group} (already attached at priority "
            f"{prio} on {acl_name}) did not match. Likely cause: a "
            f"higher-priority allow rule before it. "
            f"Console: WAFv2 → Web ACLs → {acl_name} → Rules → review "
            f"priorities < {prio}."
        )
    return {
        "suggested_actions": [action],
        "evidence_samples": _evidence_uris(matching),
    }


def _smart_count_mode(
    finding: Dict[str, Any],
    rules_by_name: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    affected = finding.get("affected_rules") or []
    if not affected:
        return None
    rule = (rules_by_name or {}).get(affected[0])
    if not rule:
        return None
    acl_name = rule.get("web_acl_name") or "the affected Web ACL"
    rule_name = rule.get("rule_name") or affected[0]
    hits = int(rule.get("hit_count") or rule.get("count_mode_hits") or 0)
    action = (
        f"Promote {rule_name} from COUNT to BLOCK on {acl_name} "
        f"(hit_count={hits:,} over 30d). False-positive review: inspect the "
        f"last 100 matched samples in CloudWatch before promotion. "
        f"Console: WAFv2 → Web ACLs → {acl_name} → Rules → Edit {rule_name} "
        f"→ Action: BLOCK → Save."
    )
    return {"suggested_actions": [action], "evidence_samples": []}


def _smart_dead_rule(
    finding: Dict[str, Any],
    rules_by_name: Dict[str, Dict[str, Any]],
    suspicious_sample: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    # Lazy import — keeps signature_class out of the import graph for the
    # canned-only callers (tests, build_demo_fixture).
    from services import signature_class as _sigcls  # noqa: PLC0415

    affected = finding.get("affected_rules") or []
    if not affected:
        return None
    rule = (rules_by_name or {}).get(affected[0])
    if not rule:
        return None
    intent = _sigcls.classify_rule_intent(
        rule.get("statement_json"), rule.get("rule_name") or "",
    )
    if not intent:
        return None
    observed = _suspicious_for_sig(suspicious_sample, intent)
    if not observed:
        # Intent known but no live evidence — canned copy is more honest.
        return None
    acl_name = rule.get("web_acl_name") or "the affected Web ACL"
    n = len(observed)
    action = (
        f"Rule {rule['rule_name']} on {acl_name} appears intended to block "
        f"{intent} but has zero hits. Meanwhile {n} {intent}-shaped "
        f"request{'s' if n != 1 else ''} reached origin in this audit. "
        f"Either the rule's match statement is broken (likely a field-name "
        f"or encoding mismatch — audit the rule definition) OR the rule is "
        f"on the wrong Web ACL. Console: WAFv2 → Web ACLs → {acl_name} → "
        f"Rules → Edit {rule['rule_name']} → review Statement JSON."
    )
    return {
        "suggested_actions": [action],
        "evidence_samples": _evidence_uris(observed),
    }


def _smart_orphan(
    finding: Dict[str, Any],
    rules_by_name: Dict[str, Dict[str, Any]],
    rules_by_acl: Dict[str, List[Dict[str, Any]]],
    web_acls: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    # Find ACL name. Affected rules are the inert rule names; first one's
    # `web_acl_name` is the orphan. Fall back to parsing the title.
    acl_name: Optional[str] = None
    affected = finding.get("affected_rules") or []
    if affected:
        first = (rules_by_name or {}).get(affected[0])
        if first:
            acl_name = first.get("web_acl_name")
    if not acl_name:
        m = _ORPHAN_TITLE_RE.search(finding.get("title") or "")
        if m:
            acl_name = m.group(1)
    if not acl_name:
        return None
    acl = next(
        (a for a in web_acls or [] if a.get("name") == acl_name), None,
    )
    scope = (acl or {}).get("scope") or "REGIONAL"
    inert_count = len(rules_by_acl.get(acl_name) or affected)
    action = (
        f"Web ACL {acl_name} (scope: {scope}) has no attached resources. "
        f"{inert_count} rule{'s' if inert_count != 1 else ''} inside "
        f"{'are' if inert_count != 1 else 'is'} inert by definition. Either "
        f"attach to a resource OR delete to stop the $5/mo fee. Console: "
        f"WAFv2 → Web ACLs → {acl_name} → Associated AWS resources → Add "
        f"(or top-right Delete)."
    )
    return {"suggested_actions": [action], "evidence_samples": []}


def smart_remediation_for(
    finding: Dict[str, Any],
    rules_by_name: Optional[Dict[str, Dict[str, Any]]] = None,
    rules_by_acl: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    web_acls: Optional[List[Dict[str, Any]]] = None,
    suspicious_sample: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """Feat #2 — return account-aware remediation for a finding, or None.

    Returning None means "fall back to the canned `remediation_for` copy".

    Supported finding types:
      * `bypass_candidate`
      * `count_mode_with_hits` / `count_mode_high_volume` /
        `count_mode_long_duration`
      * `dead_rule` (only when log-sample correlation is present)
      * `orphaned_web_acl`

    All other types intentionally return None — Flavor B is explicitly
    scoped to the four highest-value cases per Issue #2.
    """
    rules_by_name = rules_by_name or {}
    rules_by_acl = rules_by_acl or {}
    web_acls = web_acls or []
    suspicious_sample = suspicious_sample or []
    ftype = finding.get("type") or ""
    if ftype == "bypass_candidate":
        return _smart_bypass(finding, rules_by_acl, suspicious_sample)
    if ftype in {"count_mode_with_hits", "count_mode_high_volume",
                  "count_mode_long_duration"}:
        return _smart_count_mode(finding, rules_by_name)
    if ftype == "dead_rule":
        return _smart_dead_rule(finding, rules_by_name, suspicious_sample)
    if ftype == "orphaned_web_acl":
        return _smart_orphan(finding, rules_by_name, rules_by_acl, web_acls)
    return None
