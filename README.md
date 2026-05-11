# RuleIQ

AI-powered AWS WAF audit tool. Two-pass LLM pipeline that explains every WAF rule and surfaces dead rules, potential bypasses, conflicts, quick wins, and FMS-managed review items — without ever recommending changes the customer cannot make.

## Why RuleIQ

1. **Find active security gaps.** Detect attack patterns reaching origin (shellshock-class bypasses, URL-encoded XSS, SQLi probes) by analyzing what the WAF allowed vs. what should have been blocked. RuleIQ inspects real CloudWatch log traffic, not just rule definitions.
2. **Hand-off-ready audit artifact.** A single PDF a security engineer takes to a SOC2 / PCI / ISO27001 auditor — replaces weeks of manual rule documentation. Every finding includes canned remediation guidance with verify-by steps.
3. **Cut through rule rot.** Find rules with no institutional memory, no current traffic match, COUNT-mode states that have been forgotten, and stale assumptions about what's "still on." Surface them with context for safe cleanup.
4. **Onboarding accelerator.** A new security hire understands the WAF posture in 10 minutes vs. 3 weeks of console spelunking. The Web ACL Attachment + Rule Inventory tables answer "what protects what" without paging through 8 AWS console screens.
5. **M&A / due diligence.** Audit a target company's WAF posture in minutes during deal evaluation — fold the PDF straight into the data-room deliverables.
6. **Operational continuous monitoring _(roadmap)_.** Weekly delta reports + Slack alerts on HIGH findings catch config drift in days, not at the next annual audit.
7. **Cost optimization (bonus).** Dead rules and orphaned ACLs incur fixed monthly fees regardless of traffic. RuleIQ surfaces the dollar number, but treat it as a hygiene signal, not the headline.

## Phase status

- **Phase 0** (deployed): FastAPI shell, fixture rules, two-pass pipeline.
- **Phase 1** (deployed): Audit lifecycle, MongoDB persistence, scoring, demo seed.
- **Phase 2** (deployed): real boto3 reads via cross-account `sts.assume_role`, customer onboarding via Quick-Create CFN, GHA workflow race fix, prompt tuning.
- **Phase 3** (this build): React + Tailwind + Vite frontend (Connect / Results / History views), multi-stage Dockerfile that bakes the built SPA into the runtime image, `findings_count` aggregation on `/api/audits` (single `$group` query — no N+1).

## Repository layout

```
backend/
  main.py                       # FastAPI app + conditional SPA mount
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
    test_phase2.py              # 16 tests
    test_phase3.py              # 6 tests (findings_count + SPA mount)
  requirements.txt
frontend/                       # Phase 3 — React 18 + Vite 5 + Tailwind 3
  index.html
  vite.config.js
  tailwind.config.js
  src/
    App.jsx                     # state-based view router (no react-router)
    api.js                      # tiny fetch wrapper, same-origin in prod
    views/
      Connect.jsx               # Quick-Create CFN flow + role ARN form
      Results.jsx               # poll audit, summary tiles, findings + rules table
      History.jsx               # prior audits w/ findings_count column
    __tests__/
      connect.test.jsx          # 2 vitest + RTL tests
cloudformation/customer-role.yaml
scripts/
  setup-public-bucket.sh
  grant-deployer-s3-perm.sh
  setup-test-waf.sh
  teardown-test-waf.sh
docs/known_issues.md
Dockerfile                      # multi-stage: node:20 → python:3.12-slim
.github/workflows/deploy.yml
```

## Local development

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
RULEIQ_TESTING=1 pytest tests/        # 38 tests, all green; mocks OpenAI + Mongo + AWS

# Frontend (Phase 3)
cd ../frontend
yarn install
yarn dev                              # http://localhost:3000  (proxies via VITE_API_BASE)
yarn build                            # writes dist/ — what the runtime image serves
yarn test                             # vitest + React Testing Library
```

When `RULEIQ_SPA_DIST` (default `/app/static` in the container) points to a directory containing `index.html`, FastAPI mounts it at `/`. API routes (`/api/*`) are registered first and therefore always win over the SPA catch-all. If the directory is missing the mount is silently skipped, so `pytest` and pure-API local dev are unaffected.

## Phase 5.2 — IAM permissions required for full attachment detection

The customer audit role (`cloudformation/customer-role.yaml`) needs TWO permissions to
correctly enumerate Web ACL attachments and avoid "Unknown" status in the PDF:

- `wafv2:ListResourcesForWebACL` — regional ALB / API Gateway / AppSync attachments
- `cloudfront:ListDistributions`  — CloudFront-scope ACL attachments (`wafv2`'s
  own `ListResourcesForWebACL` is documented but unreliable for CloudFront)

Both are included in the updated CFN template. If you have a live role that was
created before Phase 5.2, attach them as inline policies for IMMEDIATE effect
(faster than re-running the CFN stack update):

```bash
ROLE_NAME=ruleiq-audit-role   # or whatever your role is named

aws iam put-role-policy \
  --role-name $ROLE_NAME \
  --policy-name RuleIQWafv2ListResources \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"wafv2:ListResourcesForWebACL","Resource":"*"}]}'

aws iam put-role-policy \
  --role-name $ROLE_NAME \
  --policy-name RuleIQCFListDistributions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudfront:ListDistributions","Resource":"*"}]}'
```

IAM propagation typically takes 5–15 seconds. RuleIQ's `list_resources_for_web_acl`
already retries once after a 2-second backoff on AccessDenied to hedge the
propagation window.

## Phase 5.2.2 — IAM permissions for friendly resource names

Phase 5.2.2 enriches Web ACL attachments with human-readable names (CloudFront
DomainName / custom alias, ALB DNSName, API Gateway name) so the PDF and the
UI show `aitrading.ninja` instead of
`arn:aws:cloudfront::371126261144:distribution/EKOXAVPA9GX2R`. The lookups are
optional — any AccessDenied is caught and the friendly field falls back to
`None`, so the audit never fails on missing perms.

Required actions on the audit role to populate friendly names:

- `cloudfront:GetDistribution`             — CloudFront alias / domain lookup
- `elasticloadbalancing:DescribeLoadBalancers` — ALB DNSName
- `apigateway:GET`                         — API Gateway REST/HTTP API name
- `cognito-idp:DescribeUserPool`           — Cognito user pool name (optional)

All of these are included in the updated `cloudformation/customer-role.yaml`.
If you already created the role pre-5.2.2, attach them inline (faster than a
CFN stack update):

```bash
ROLE_NAME=ruleiq-audit-role   # or whatever your role is named

aws iam put-role-policy \
  --role-name $ROLE_NAME \
  --policy-name RuleIQResourceFriendlyNames \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["elasticloadbalancing:DescribeLoadBalancers","apigateway:GET","cognito-idp:DescribeUserPool","cloudfront:GetDistribution"],"Resource":"*"}]}'
```

### Environment variables (deployed)

| Variable                          | Purpose                                                 | Default              |
|-----------------------------------|---------------------------------------------------------|----------------------|
| `OPENAI_API_KEY`                  | Overrides Secrets Manager fetch                         | unset                |
| `MONGODB_URI`                     | Overrides Secrets Manager fetch                         | unset                |
| `DEMO_MODE`                       | When `true`, audits use fixtures even with `role_arn`   | `true`               |
| `RULEIQ_APP_RUNNER_ACCOUNT_ID`    | Account that hosts RuleIQ; baked into CFN trust policy  | `<ACCOUNT_ID>`       |
| `RULEIQ_PUBLIC_TEMPLATES_BUCKET`  | Public S3 bucket holding `customer-role.yaml`           | `ruleiq-public-templates-<account>` |
| `PORT`                            | uvicorn port                                            | `8080`               |

## Phase 2 — running a real audit

End-to-end onboarding sequence. Run **once** in CloudShell with admin AWS creds for the RuleIQ account (`<ACCOUNT_ID>`):

```bash
# 1. Public-read S3 bucket for the CFN template
bash scripts/setup-public-bucket.sh

# 2. Grant the GHA deployer role permission to write that bucket
bash scripts/grant-deployer-s3-perm.sh
```

Then push Phase 2 from your Cloud9 repo (commands at the bottom of this README). The GHA workflow will:
- Build & push the new image to ECR
- Sync `cloudformation/customer-role.yaml` to `s3://ruleiq-public-templates-<ACCOUNT_ID>/customer-role.yaml`
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
| Account / region | `<ACCOUNT_ID>` / `us-east-1`                                                 |
| ECR repo         | `<ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/ruleiq`                        |
| Deployer role    | `arn:aws:iam::<ACCOUNT_ID>:role/ruleiq-github-deployer`                      |
| Instance role    | `arn:aws:iam::<ACCOUNT_ID>:role/ruleiq-apprunner-instance`                   |
| Access role      | `arn:aws:iam::<ACCOUNT_ID>:role/ruleiq-apprunner-ecr-access`                 |
| OpenAI secret    | `arn:aws:secretsmanager:us-east-1:<ACCOUNT_ID>:secret:ruleiq/openai`         |
| Mongo secret     | `arn:aws:secretsmanager:us-east-1:<ACCOUNT_ID>:secret:ruleiq/mongodb`        |
| Public templates | `s3://ruleiq-public-templates-<ACCOUNT_ID>/customer-role.yaml`               |
