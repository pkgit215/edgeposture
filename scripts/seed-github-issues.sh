#!/usr/bin/env bash
# RuleIQ — seed initial issues. Run from repo root with gh CLI authenticated.
#
# Idempotent — issues whose title already exists in the repo are skipped.
# Re-run safely.
set -euo pipefail

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: 'gh' CLI not found on PATH." >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "ERROR: 'gh' is not authenticated. Run 'gh auth login' first." >&2
  exit 1
fi

# Build a newline-separated list of existing issue titles (open + closed).
EXISTING_TITLES=$(gh issue list --state all --limit 1000 --json title -q '.[].title' || true)

create_issue() {
  local title="$1"
  shift
  local labels="$1"
  shift
  local body="$1"
  if echo "$EXISTING_TITLES" | grep -Fxq "$title"; then
    echo "skip (exists): $title"
    return 0
  fi
  echo "create:       $title"
  gh issue create \
    --title "$title" \
    --label "$labels" \
    --body  "$body"
}

# -----------------------------------------------------------------------------
# P1 — current sprint priorities
# -----------------------------------------------------------------------------

create_issue \
  "[bug] LegacyDeadRule severity rubric over-correlates bypass findings" \
  "type:bug,priority:p1,area:scoring" \
  "$(cat <<'BODY'
Phase 5.3.2's severity correlation in `audit.py::run_audit_pipeline` keeps
`dead_rule` findings at HIGH if ANY `bypass_candidate` exists in the audit.

**Correct behaviour:** a custom `dead_rule` defaults to MEDIUM. Only escalate
to HIGH if the dead rule's intent matches the bypass signature class
(shellshock / sqli / xss / unix / etc).

**Quick-fix path:** drop correlation entirely, dead_rule always MEDIUM.

**Smart-fix path:** tracked as separate issue ([feat] signature-class correlation).
BODY
)"

create_issue \
  "[feat] Flavor B remediation — per-account inspection" \
  "type:feature,priority:p1,area:remediation" \
  "$(cat <<'BODY'
Upgrade the canned remediation block to inspect THIS specific account and
propose concrete actions: which managed rule group is missing, suggested
priority slot, citations to log samples that would have been blocked,
exact AWS console navigation path.

See chat transcript dated 2026-05-11 ("Flavor B").

**Acceptance:** a `bypass_candidate` finding for shellshock includes
copy of the shape:

> "Add `AWSManagedRulesKnownBadInputsRuleSet` at priority N to
> `<web_acl_name>` — N attack-shaped requests reached origin in the
> last 30d. Console path: WAFv2 → Web ACLs → `<name>` → Rules → Add
> managed rule group."
BODY
)"

create_issue \
  "[chore] Validate COUNT-mode + override findings against real traffic" \
  "type:chore,priority:p1,area:scoring" \
  "$(cat <<'BODY'
COUNT-mode finding types (`count_mode_with_hits`, `count_mode_high_volume`,
`count_mode_long_duration`) ship in Phase 5.3 but have not fired against
real production traffic — the test account has no COUNT-mode rules.

**Steps:**
1. Flip `BlockOldCurlScanners` to COUNT mode in the AWS console.
2. Run `waf-smoke.sh` from Cloud9 to generate ~800 attack-shaped curl requests.
3. Re-run a RuleIQ audit.
4. Confirm `count_mode_with_hits` and `managed_rule_override_count` findings
   appear with non-empty `suggested_actions` / `verify_by` / `disclaimer`.

Close when an audit shows all three COUNT-mode finding types firing correctly.
BODY
)"

# -----------------------------------------------------------------------------
# P2 — next quarter
# -----------------------------------------------------------------------------

create_issue \
  "[feat] Signature-class correlation for dead_rule severity escalation" \
  "type:feature,priority:p2,area:scoring" \
  "$(cat <<'BODY'
Smart version of the bug "LegacyDeadRule severity rubric over-correlates
bypass findings".

Parse each rule's `statement_json` to extract its intent signature class
(shellshock, sqli, xss, unix, rate-limit, curl-ua, ip-block, etc). Tag
each entry in `suspicious_request_sample` with the same class. If a dead
rule's class overlaps with anything in the sample, escalate severity to
HIGH. Otherwise MEDIUM.

Requires a class lookup table + AI fallback for ambiguous statements.
BODY
)"

create_issue \
  "[feat] URL-encoded payload decoding in suspicion scorer" \
  "type:feature,priority:p2,area:scoring" \
  "$(cat <<'BODY'
`backend/services/aws_waf.py::score_request_suspicion` misses attack
patterns in URL-encoded URIs (e.g., `%3Cscript%3E` for `<script>`).
Decode URIs once before pattern matching.

**Acceptance:** regression test with `/%3Cscript%3Ealert(1)%3C/script%3E`
produces a XSS suspicion score equal to its decoded form.
BODY
)"

create_issue \
  "[feat] CSV export of Web ACL attachment inventory" \
  "type:feature,priority:p2,area:frontend,area:backend" \
  "$(cat <<'BODY'
Add `GET /api/audits/{id}/attachments.csv` and a "Download CSV" button on
the Results page.

Columns: `web_acl_name`, `scope`, `region`, `attached_resource_type`,
`attached_resource_arn`, `attached_resource_friendly_name`.
BODY
)"

create_issue \
  "[feat] UI provenance badge for log-sample evidence" \
  "type:feature,priority:p2,area:frontend,area:methodology" \
  "$(cat <<'BODY'
Findings with `evidence='log-sample'` should show a small badge on the
FindingCard linking to the `suspicious_request_sample` row that produced
the finding. Tied to the Methodology tab "Evidence types" section.
BODY
)"

create_issue \
  "[feat] Slack / Teams webhook on HIGH findings" \
  "type:feature,priority:p2,area:integrations" \
  "$(cat <<'BODY'
Configurable webhook URL per account. POST a compact summary on every
audit completion where `high_count > 0`. Use Block Kit / Adaptive Card.
BODY
)"

# -----------------------------------------------------------------------------
# P3 — backlog
# -----------------------------------------------------------------------------

create_issue \
  "[feat] Authenticated scans + ZAP integration helpers" \
  "type:feature,priority:p3,area:integrations" \
  "$(cat <<'BODY'
Drive authenticated request generation through ZAP / Burp so we can test
WAF rules behind login flows.
BODY
)"

create_issue \
  "[feat] Scheduled audits (weekly cron)" \
  "type:feature,priority:p3,area:integrations" \
  "$(cat <<'BODY'
Per-account weekly audit cron. Email delta report on changes.
BODY
)"

create_issue \
  "[feat] Multi-region audit scan" \
  "type:feature,priority:p3,area:backend" \
  "$(cat <<'BODY'
Walk every AWS region the account uses and audit Regional WebACLs in each.
CloudFront stays us-east-1 only.
BODY
)"

create_issue \
  "[feat] App authentication (login on RuleIQ itself)" \
  "type:feature,priority:p3,area:backend,area:frontend" \
  "$(cat <<'BODY'
Add account login (email + password OR Google OIDC). Required before any
multi-tenant rollout.
BODY
)"

create_issue \
  "[feat] Audit history diff (compare two runs)" \
  "type:feature,priority:p3,area:frontend,area:backend" \
  "$(cat <<'BODY'
"Diff" view on the History screen — pick two audits, show added /
removed / severity-changed findings.
BODY
)"

create_issue \
  "[chore] Migration plan — App Runner → ECS Express Mode" \
  "type:chore,priority:p3,area:deployment" \
  "$(cat <<'BODY'
Track AWS App Runner deprecation. Existing POC stays on App Runner;
net-new environments must target ECS Express Mode. Includes a Runbook for
cold-start setup (cluster, service, task def, ALB).
BODY
)"

create_issue \
  "[feat] Multi-cloud — Cloudflare, Akamai, Fastly WAF audits" \
  "type:feature,priority:p3,area:multicloud" \
  "$(cat <<'BODY'
Generalise the ingestion layer behind a `WAFProvider` interface and add
Cloudflare / Akamai / Fastly adapters. Each provider has its own
config-fetch + log-sampling story.
BODY
)"

create_issue \
  "[feat] Drift-back-to-IaC export (Terraform / CloudFormation / CDK)" \
  "type:feature,priority:p3,area:backend" \
  "$(cat <<'BODY'
For each Web ACL, emit equivalent Terraform / CloudFormation / CDK
snippet for the rule set. Closes the "audit found drift — now how do I
codify it" loop.
BODY
)"

create_issue \
  "[feat] \"Email this PDF to my auditor\" button" \
  "type:feature,priority:p3,area:frontend,area:backend" \
  "$(cat <<'BODY'
SES + recipient email field on the Results page. Logs every send into an
audit-trail collection. Subject line: "RuleIQ audit — <account_id> —
<date>".
BODY
)"

create_issue \
  "[feat] ?print=true query-string for browser-printable Results view" \
  "type:feature,priority:p3,area:frontend" \
  "$(cat <<'BODY'
Cheap third deliverable format alongside JSON + PDF. Pre-expand all
finding accordions, inline the Methodology tab, hide tab bar / nav, then
trigger `window.print()`.
BODY
)"

create_issue \
  "[chore] /api/version endpoint with git SHA + build timestamp" \
  "type:chore,priority:p3,area:backend" \
  "$(cat <<'BODY'
Replaces the ambiguous `/api/health.phase` string. Build-time injection of
`GIT_SHA` and `BUILD_TIME` env vars in the Dockerfile; FastAPI reads and
echoes them.
BODY
)"

create_issue \
  "[chore] Domain acquisition for RuleIQ" \
  "type:chore,priority:p3,area:deployment" \
  "$(cat <<'BODY'
`ruleiq.com`, `.io`, `.ai` are all registered. Pursue `ruleiq.com` via
GoDaddy "Make Offer" or a domain broker. Ceiling: \$1,500 USD.

Fallback: pick a fresh name from the candidate list. Do NOT use
`wafruleiq`.
BODY
)"

echo
echo "Done. Run 'gh issue list' to verify."
