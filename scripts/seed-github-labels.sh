#!/usr/bin/env bash
# RuleIQ — seed canonical label set. Run from repo root with gh CLI authenticated.
#
# Idempotent — already-exists errors are swallowed; mismatched colors are
# corrected via `gh label edit`. Re-run safely.
set -euo pipefail

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: 'gh' CLI not found on PATH." >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "ERROR: 'gh' is not authenticated. Run 'gh auth login' first." >&2
  exit 1
fi

# (name|color|description) — must mirror .github/labels.yml exactly.
LABELS=(
  "priority:p0|b60205|Drop everything"
  "priority:p1|d93f0b|Current sprint"
  "priority:p2|fbca04|Next quarter"
  "priority:p3|cccccc|Backlog"
  "type:bug|ee0701|Something is broken"
  "type:feature|1d76db|New capability"
  "type:chore|bfd4f2|Cleanup, refactor, infra"
  "type:docs|c5def5|Documentation"
  "type:security|b60205|Security finding"
  "area:backend|5319e7|FastAPI / services"
  "area:frontend|0e8a16|React SPA"
  "area:pdf|fbca04|PDF audit report rendering"
  "area:methodology|d4c5f9|Methodology tab + PDF appendix"
  "area:scoring|f9d0c4|Severity / confidence / score calibration"
  "area:remediation|bfe5bf|Canned + per-account remediation"
  "area:iam|fef2c0|IAM roles, policies, STS"
  "area:deployment|c2e0c6|App Runner, ECS, infra rollouts"
  "area:multicloud|1d76db|Non-AWS WAF audits"
  "area:integrations|5319e7|Slack / email / scheduled / ZAP etc"
  "status:blocked|b60205|Waiting on external dep"
  "status:in-progress|fbca04|Actively being worked on"
  "status:needs-review|0e8a16|PR open, waiting on review"
  "good-first-issue|7057ff|Friendly entry point for new contributors"
)

for row in "${LABELS[@]}"; do
  IFS='|' read -r name color desc <<< "$row"
  if gh label create "$name" --color "$color" --description "$desc" 2>/dev/null; then
    echo "create: $name"
  else
    # Either already exists or hit a transient error — try update; ignore failures.
    if gh label edit "$name" --color "$color" --description "$desc" >/dev/null 2>&1; then
      echo "update: $name"
    else
      echo "skip:   $name (already correct or unauthorised)"
    fi
  fi
done

echo
echo "Done. Run 'gh label list' to verify."
