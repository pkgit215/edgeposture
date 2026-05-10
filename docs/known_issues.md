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


## Phase 3 hot-fix: rotating `EXTERNAL_ID_SECRET`

The deterministic per-tenant ExternalId is computed as
`HMAC-SHA256(EXTERNAL_ID_SECRET, account_id)[:32]`. The secret lives in AWS
Secrets Manager at
`arn:aws:secretsmanager:us-east-1:371126261144:secret:ruleiq/external-id-secret`
and is injected into App Runner as an env var via `RuntimeEnvironmentSecrets`.

**Bootstrap (one-time):** run `scripts/setup-external-id-secret.sh`. It
creates the secret with a 64-hex-char random value and grants the App Runner
instance role read access. Idempotent — running it again on an existing
secret leaves the value untouched.

**Rotation policy:** rotating the secret invalidates **every** customer's
existing IAM trust policy. Their roles bind the OLD ExternalId; after a
rotation `setup-info` will hand out a NEW ExternalId for the same account ID,
and `sts:AssumeRole` will fail until each customer recreates the role via the
fresh Quick-Create CFN URL.

Rotation runbook (only do this if the secret is suspected leaked):

1. Email/notify every active tenant: "Your IAM trust role will need to be
   recreated within 24 h. We are rotating our HMAC key."
2. `aws secretsmanager update-secret --secret-id ruleiq/external-id-secret
   --secret-string "$(python3 -c 'import secrets;print(secrets.token_hex(32))')"`
3. Trigger a redeploy of the App Runner service so the new value gets
   injected (`gh workflow run deploy.yml` or push any commit to `main`).
4. Each customer hits `/api/setup-info?account_id=…`, gets the new
   ExternalId, and re-runs the Quick-Create CFN stack to update their
   trust policy.

If `EXTERNAL_ID_SECRET` is unreachable on boot (Secrets Manager auth fails or
the env var is unset), the backend falls back to a process-level random
constant and logs a `WARNING`. The app stays up; ExternalIds become stable
for the lifetime of that one process and rotate at every restart. This is
fine for local dev but visibly broken in prod — fix the wiring instead of
ignoring the warning.
