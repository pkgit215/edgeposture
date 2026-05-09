# RuleIQ — known issues

Live observations from earlier phase reviews. Each entry is intentionally
verbatim from the phase brief that surfaced it; do not rewrite without
linking back to the originating phase.

## From Phase 0 → Phase 1 review

- `BlockOldStagingHeader` (zero hits, stale 2019 header pattern) was not flagged
  as a `dead_rule` by Pass 2 in the live run, while `BlockLegacyAdminPath` (also
  zero hits) was flagged. Inconsistent treatment of similar rules. Defer fix to
  Phase 2 prompt tuning when we have real rules to validate against.

- Pass 1 explainer set `working: true` for `BlockLegacyAdminPath` while Pass 2
  correctly produced a `dead_rule` finding for it. The contradiction is not
  surfaced today but will look odd when the rule browser (Phase 3) shows the
  explanation alongside findings. Phase 3 UI must reconcile — when a rule
  appears in any `dead_rule`/`bypass_candidate` finding, the rule card should
  display the finding's framing (not the Pass-1 explanation's "working"
  assertion).
