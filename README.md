# RuleIQ

AI-powered AWS WAF audit tool. Two-pass LLM pipeline that explains every WAF rule and surfaces dead rules, potential bypasses, conflicts, quick wins, and FMS-managed review items — without ever recommending changes the customer cannot make.

## Phase status

- **Phase 0** (deployed): FastAPI shell, fixture rules, two-pass pipeline.
- **Phase 1** (deployed): Audit lifecycle, MongoDB persistence, scoring, demo seed.
- **Phase 2** (this build): real boto3 reads via cross-account `sts.assume_role`, customer onboarding via Quick-Create CFN, GHA workflow race fix, prompt tuning.
- Phase 3 (next): React + Tailwind frontend.

## Repository layout

```
backend/
  main.py                       # FastAPI app
  models.py                     # Pydantic v2
  fixtures/waf_rules.json
  services/
    ai_pipeline.py              # Pass 1 + Pass 2 (gpt-4o, JSON mode)
    aws_waf.py                  # boto3 wafv2 / logs / fms / sts (Phase 2)
    audit.py                    # hybrid demo/real audit worker
    db.py                       # pymongo singleton + index ensure
    scoring.py                  # severity_score, estimated_waste_usd, breakdown
    secrets.py                  # env-first → Secrets Manager
    seed.py                     # idempotent demo seed
  tests/
    test_phase0.py              # 7 tests
    test_phase1.py              # 9 tests
    test_phase2.py              # 11 tests
  requirements.txt
cloudformation/customer-role.yaml  # IAM role customers create via Quick-Create
scripts/
  setup-public-bucket.sh        # one-time S3 bucket for CFN template hosting
  grant-deployer-s3-perm.sh     # one-time IAM perm for GHA → that bucket
  setup-test-waf.sh             # builds a disposable WAF + seeds traffic
  teardown-test-waf.sh          # tears it all down
docs/known_issues.md
Dockerfile
.github/workflows/deploy.yml
```

## Local development

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
RULEIQ_TESTING=1 pytest tests/        # 27 tests, all green; mocks OpenAI + Mongo + AWS
```

### Environment variables (deployed)

| Variable                          | Purpose                                                 | Default              |
|-----------------------------------|---------------------------------------------------------|----------------------|
| `OPENAI_API_KEY`                  | Overrides Secrets Manager fetch                         | unset                |
| `MONGODB_URI`                     | Overrides Secrets Manager fetch                         | unset                |
| `DEMO_MODE`                       | When `true`, audits use fixtures even with `role_arn`   | `true`               |
| `RULEIQ_APP_RUNNER_ACCOUNT_ID`    | Account that hosts RuleIQ; baked into CFN trust policy  | `371126261144`       |
| `RULEIQ_PUBLIC_TEMPLATES_BUCKET`  | Public S3 bucket holding `customer-role.yaml`           | `ruleiq-public-templates-<account>` |
| `PORT`                            | uvicorn port                                            | `8080`               |

## Phase 2 — running a real audit

End-to-end onboarding sequence. Run **once** in CloudShell with admin AWS creds for the RuleIQ account (`371126261144`):

```bash
# 1. Public-read S3 bucket for the CFN template
bash scripts/setup-public-bucket.sh

# 2. Grant the GHA deployer role permission to write that bucket
bash scripts/grant-deployer-s3-perm.sh
```

Then push Phase 2 from your Cloud9 repo (commands at the bottom of this README). The GHA workflow will:
- Build & push the new image to ECR
- Sync `cloudformation/customer-role.yaml` to `s3://ruleiq-public-templates-371126261144/customer-role.yaml`
- Trigger an App Runner deploy if no auto-deploy is already in flight (race fix below)

Once App Runner is `RUNNING`, build the disposable test WAF + seed traffic in the **target audit account** (can be the same account or a different one — the role trust policy uses ExternalId, not account-anchoring):

```bash
# 3. Create disposable WAF + 5,000 seeded log events
export RULEIQ_URL=https://<your-app-runner-host>
bash scripts/setup-test-waf.sh
```

`setup-test-waf.sh` prints:
- The Quick-Create CFN URL (fetched from `GET /api/setup-info`)
- The current `ExternalId` you'll need
- The exact `curl` command to POST `/api/audits` after the stack reaches `CREATE_COMPLETE`

Click the Quick-Create link, accept role creation, copy the `RoleArn` output, then run the printed `curl`. Poll:

```bash
curl $RULEIQ_URL/api/audits | jq '.[0]'
# wait for status=="complete"
curl $RULEIQ_URL/api/audits/<id>/findings | jq '.[] | {type, severity_score, affected_rules}'
```

Expected on the seeded test WAF: `rule_count=4`, `BlockBadIPs/RateLimitGlobal/BlockAdminPath` non-zero hits, `LegacyDeadRule` zero hits, a `dead_rule` finding for `LegacyDeadRule`, and `estimated_waste_breakdown` listing it at `$1/month`.

To clean up: `bash scripts/teardown-test-waf.sh` (deletes the WebACL, IPSet, log group, and the `RuleIQAuditRole` CFN stack).

### GHA workflow race fix

Phase 0/1's deploy step called `aws apprunner start-deployment` unconditionally. With `AutoDeploymentsEnabled=true`, the ECR push itself triggers a deploy, and the explicit `start-deployment` then 254s with `OperationInProgressException`. Phase 2 reads `Service.Status` first:

| Status                  | Action                                                         |
|-------------------------|----------------------------------------------------------------|
| `RUNNING`               | Call `start-deployment` explicitly                             |
| `OPERATION_IN_PROGRESS` | Skip — auto-deploy already handling it                         |
| `CREATE_FAILED` / etc.  | Fail loudly                                                    |

## FMS suppression contract

FMS-managed rules (`fms_managed=true`) are owned by a delegated admin account and cannot be modified by the customer. Pass 2 is hard-instructed to never emit `dead_rule` or `quick_win` findings against them; instead it emits `fms_review` findings recommending escalation to the central security team. Tests enforce this in all three phases.

## Phase 2 sampling limitation (verbatim from `services/aws_waf.py`)

> Most-recent 50,000 events per rule, sorted desc by timestamp, 30-day window. If the rule has more than 50k hits in 30d, sample_uris and count_mode_hits reflect only the most recent slice — the hit_count is also capped at 50k. This is a known sampling limitation; bump max_events or move to Athena over S3 for high-traffic accounts.

## AWS resources used

| Resource         | ARN / value                                                                  |
|------------------|------------------------------------------------------------------------------|
| Account / region | `371126261144` / `us-east-1`                                                 |
| ECR repo         | `371126261144.dkr.ecr.us-east-1.amazonaws.com/ruleiq`                        |
| Deployer role    | `arn:aws:iam::371126261144:role/ruleiq-github-deployer`                      |
| Instance role    | `arn:aws:iam::371126261144:role/ruleiq-apprunner-instance`                   |
| Access role      | `arn:aws:iam::371126261144:role/ruleiq-apprunner-ecr-access`                 |
| OpenAI secret    | `arn:aws:secretsmanager:us-east-1:371126261144:secret:ruleiq/openai`         |
| Mongo secret     | `arn:aws:secretsmanager:us-east-1:371126261144:secret:ruleiq/mongodb`        |
| Public templates | `s3://ruleiq-public-templates-371126261144/customer-role.yaml`               |
