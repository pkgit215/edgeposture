# EdgePosture — developer notes

Internal docs for contributors and maintainers. Customer-facing material
lives in [`README.md`](../README.md). For the PR / branch / commit
conventions, see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Local development

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
EDGEPOSTURE_TESTING=1 pytest tests/         # all backend tests; mocks OpenAI + Mongo + AWS
DEMO_MODE=true uvicorn main:app --reload --port 8001

# Frontend
cd ../frontend
yarn install
yarn dev                               # http://localhost:5173
yarn build                             # writes dist/ — what the runtime image serves
yarn vitest run                        # vitest + React Testing Library
```

When `RULEIQ_SPA_DIST` (default `/app/static` in the container) points to
a directory containing `index.html`, FastAPI mounts the SPA at `/`. API
routes (`/api/*`) are registered first and always win over the SPA
catch-all. If the directory is missing the mount is silently skipped, so
`pytest` and pure-API local dev are unaffected.

## Required GitHub repo variables / secrets

The GitHub Actions deploy workflow reads these from Settings → Secrets
and variables → Actions:

| Kind     | Name                  | Purpose                                                                 |
|----------|-----------------------|-------------------------------------------------------------------------|
| Variable | `AWS_ACCOUNT_ID`      | EdgePosture host AWS account ID. All ARNs in the workflow resolve through it |
| Secret   | `OPENAI_API_KEY`      | Pulled from Secrets Manager at runtime; used by `services/ai_pipeline.py` |
| Secret   | `MONGODB_URI`         | Pulled from Secrets Manager at runtime; used by `services/db.py`        |

The deployer IAM role (`arn:aws:iam::<AWS_ACCOUNT_ID>:role/ruleiq-github-deployer`)
trusts GitHub's OIDC issuer and is scoped to ECR push + App Runner
deploy + S3 sync (for the public CloudFormation template bucket).

## Required environment variables (runtime container)

| Variable                          | Purpose                                                            | Default                                |
|-----------------------------------|--------------------------------------------------------------------|----------------------------------------|
| `OPENAI_API_KEY`                  | Overrides Secrets Manager fetch in local dev                       | unset                                  |
| `MONGODB_URI`                     | Overrides Secrets Manager fetch in local dev                       | unset                                  |
| `DEMO_MODE`                       | When `true`, audits use fixtures even with `role_arn`              | `true`                                 |
| `RULEIQ_APP_RUNNER_ACCOUNT_ID`    | Account that hosts EdgePosture; baked into customer CFN trust policy    | `<YOUR_AWS_ACCOUNT_ID>` placeholder    |
| `RULEIQ_PUBLIC_TEMPLATES_BUCKET`  | Public S3 bucket holding `customer-role.yaml`                      | `ruleiq-public-templates-<account>`    |
| `EXTERNAL_ID_SECRET`              | 64-char HMAC seed for deriving per-tenant ExternalId values        | required                               |
| `PORT`                            | uvicorn port                                                       | `8080`                                 |
| `RULEIQ_SPA_DIST`                 | Path to built Vite SPA. Empty/missing → SPA mount disabled         | `/app/static`                          |

Copy [`/.env.example`](../.env.example) to `.env` and fill in. The `.env`
file is `.gitignored`.

## Tests

```bash
cd backend  && pytest -q
cd frontend && yarn vitest run

# Credentials + PII guard. Runs as a pytest, but you can invoke it
# directly when triaging a failing pre-commit:
bash scripts/check-no-creds.sh
```

Backend pytest runs in ~5s on a laptop. Frontend `yarn vitest run` runs
in ~5s.

## Release / deploy

The release flow is **single-branch single-PR** with a tarball handoff:

1. The Emergent agent edits files inside the Emergent pod's `/app` tree.
2. The agent builds `/app/dist/ruleiq-<branch>.tar.gz` and prints the
   `sha256` + a single-line Cloud9 push command.
3. The maintainer runs that command in Cloud9. It downloads the
   tarball, verifies the sha256, untars over the working tree, commits,
   pushes the branch, and opens a PR via `gh pr create`.
4. Merging the PR to `main` triggers `.github/workflows/deploy.yml`:
   - Builds the multi-stage Dockerfile (node 20 → python 3.12-slim)
   - Pushes to ECR (`<aws_account_id>.dkr.ecr.us-east-1.amazonaws.com/ruleiq`)
   - Syncs `cloudformation/customer-role.yaml` to the public S3 bucket
   - Calls `apprunner start-deployment` — guarded against the
     `OperationInProgressException` race documented below.

### App Runner deploy race

`AutoDeploymentsEnabled=true` on the App Runner service means the ECR
push itself triggers a deploy. An unconditional `start-deployment`
afterward 4×Xs with `OperationInProgressException`. The workflow reads
`Service.Status` first:

| Status                  | Action                                                  |
|-------------------------|---------------------------------------------------------|
| `RUNNING`               | Call `start-deployment` explicitly                      |
| `OPERATION_IN_PROGRESS` | Skip — auto-deploy already handling it                  |
| `CREATE_FAILED` / etc.  | Fail loudly                                             |

### Customer onboarding artefacts (run once per EdgePosture host account)

```bash
# Create the public-read S3 bucket that hosts customer-role.yaml.
bash scripts/setup-public-bucket.sh
# Grant the GHA deployer role permission to write that bucket.
bash scripts/grant-deployer-s3-perm.sh
# Provision the per-host ExternalId derivation secret.
bash scripts/setup-external-id-secret.sh
```

A disposable test target (separate AWS account or sub-OU) can be created
with:

```bash
export RULEIQ_URL=https://<your-app-runner-host>
bash scripts/setup-test-waf.sh        # creates a WebACL + 5,000 seeded log events
# … run the audit via the printed curl …
bash scripts/teardown-test-waf.sh     # removes the WebACL, IPSet, log group, CFN stack
```

## FMS suppression contract

FMS-managed rules (`fms_managed=true`) are owned by a delegated admin
account and cannot be modified by the customer. The audit pipeline is
hard-instructed to **never** emit `dead_rule` or `quick_win` findings
against them; instead it emits `fms_review` findings recommending
escalation to the central security team. Tests enforce this end-to-end.

## CloudWatch sampling limitation

Verbatim from `services/aws_waf.py`:

> Most-recent 50,000 events per rule, sorted descending by timestamp,
> 30-day window. If the rule has more than 50k hits in 30d, sample_uris
> and count_mode_hits reflect only the most recent slice — the
> hit_count is also capped at 50k. This is a known sampling limitation;
> bump max_events or move to Athena over S3 for high-traffic accounts.

## Repository layout

```
backend/                   FastAPI + audit pipeline + scoring + remediation
  main.py                  app entrypoint, SPA static mount, CORS
  services/                pipeline modules (audit, ai_pipeline, aws_waf, etc.)
  fixtures/                local-dev WAF rule fixtures
  demo/                    committed demo audit fixture (served at /api/demo/*)
  tests/                   pytest suite — mocks OpenAI / Mongo / AWS
frontend/                  React 18 + Vite 5 + Tailwind 3
  src/views/               Connect / Results / History tabs
  src/__tests__/           vitest + React Testing Library
cloudformation/            customer-role.yaml — Quick-Create template
scripts/                   one-off setup scripts + check-no-creds.sh
docs/                      contributor docs (this file + known_issues.md)
.github/workflows/         GHA deploy + label seeding
Dockerfile                 multi-stage: node 20 → python 3.12-slim
```
