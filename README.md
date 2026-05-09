# RuleIQ

AI-powered AWS WAF audit tool. Two-pass LLM pipeline that explains every WAF rule, then surfaces dead rules, potential bypasses, conflicts, quick wins, and FMS-managed review items — without ever recommending changes the customer cannot make.

## Phase 0 scope (this build)

- FastAPI backend with three endpoints (`/api/health`, `/api/openapi.json`, `/api/poc/analyze`).
- Two-pass OpenAI pipeline (`gpt-4o`, JSON mode, tenacity retries).
- Static fixture WAF ruleset that exercises every finding type and FMS suppression rule.
- AWS Secrets Manager loader (env-var-first) for the OpenAI key and Mongo URI (Mongo URI is reserved for Phase 1 — no client is instantiated yet).
- Containerised on App Runner via GitHub Actions OIDC.

Not in Phase 0: frontend, real AWS WAF reads, MongoDB writes, background tasks, auth.

## Repository layout

```
backend/
  main.py                # FastAPI app
  fixtures/waf_rules.json
  services/
    ai_pipeline.py       # Pass 1 + Pass 2
    secrets.py           # OpenAI / Mongo secret resolver
  tests/test_phase0.py
  requirements.txt
Dockerfile
.github/workflows/deploy.yml
```

## Local development

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Tests mock OpenAI — no key required.
pytest tests/

# Manual run (needs OPENAI_API_KEY env or AWS Secrets Manager creds):
export OPENAI_API_KEY=sk-...
uvicorn main:app --host 0.0.0.0 --port 8080
curl -X POST http://localhost:8080/api/poc/analyze | jq
```

### Environment variables

| Variable        | Purpose                              | Default |
|-----------------|--------------------------------------|---------|
| `OPENAI_API_KEY`| Overrides Secrets Manager fetch      | unset   |
| `MONGODB_URI`   | Overrides Secrets Manager fetch      | unset   |
| `DEMO_MODE`     | Reserved for Phase 0 (logged, no-op) | `true`  |
| `PORT`          | Uvicorn port                         | `8080`  |

## Deployment

Push to `main` → GitHub Actions assumes `arn:aws:iam::371126261144:role/ruleiq-github-deployer` via OIDC, builds a Docker image, pushes `:<sha>` and `:latest` to `371126261144.dkr.ecr.us-east-1.amazonaws.com/ruleiq`, then either creates the App Runner service `ruleiq` (first run) or starts a deployment (subsequent runs). The job summary prints the service URL.

- GitHub Actions: <https://github.com/pkgit215/ruleiq/actions>
- App Runner console: <https://console.aws.amazon.com/apprunner/home?region=us-east-1#/services>

### AWS resources used

| Resource           | ARN / value                                                                 |
|--------------------|------------------------------------------------------------------------------|
| Account / region   | `371126261144` / `us-east-1`                                                 |
| ECR repo           | `371126261144.dkr.ecr.us-east-1.amazonaws.com/ruleiq`                        |
| Deployer role      | `arn:aws:iam::371126261144:role/ruleiq-github-deployer`                      |
| Instance role      | `arn:aws:iam::371126261144:role/ruleiq-apprunner-instance`                   |
| Access role        | `arn:aws:iam::371126261144:role/ruleiq-apprunner-ecr-access`                 |
| OpenAI secret      | `arn:aws:secretsmanager:us-east-1:371126261144:secret:ruleiq/openai` (plain) |
| Mongo secret       | `arn:aws:secretsmanager:us-east-1:371126261144:secret:ruleiq/mongodb` (JSON) |

## FMS suppression contract

FMS-managed rules (`fms_managed=true`) are owned by a delegated admin account and cannot be modified by the customer. Pass 2 is hard-instructed to never emit `dead_rule` or `quick_win` findings against them; instead it emits `fms_review` findings recommending escalation to the central security team. Tests enforce this.
