# EdgePosture — Roadmap

Milestone-per-version. Open backlog and granular work live in GitHub
Issues (filterable by `milestone:`).

## v0.1 — Beta POC (shipped)

Single-tenant audit pipeline against the maintainer's own AWS account.
What proved out: the AI Pass 1 explainer + Pass 2 findings model
produces non-trivial signal on a real WAF; the `/demo` route is enough
to land a real conversation; FastAPI + React + Atlas + App Runner is
a workable stack for this shape of product. First public deploy:
May 2026.

## v0.2 — SaaS MVP (in progress)

Make EdgePosture safe to invite a second human onto. The Epic at #45
breaks this down into five subtasks; each lands as its own PR.

- [x] Item 3 — Google OAuth + tenants + sessions (shipped May 12, 2026)
- [ ] Item 1 — Per-customer ExternalId on AssumeRole
- [ ] Item 2 — MongoDB tenant scoping (tenant_id on every collection, isolation tests)
- [ ] Item 4 — Tenant-aware onboarding flow (CFN Quick-Create wizard, first-audit-on-signup)
- [ ] Item 5 — Rate limiting + per-tenant usage log + OpenAI cost guardrails

## v0.3 — Production-hardened

Once a second human is onboarded, the rough edges around how the
service is run start to matter. Scope:

- Migrate deployment to a dedicated `ProductionApp` AWS sub-account, out
  of the management account (least-privilege + blast-radius isolation).
- Rename customer-visible `ruleiq-*` AWS resources to `edgeposture-*`
  (ECR repo, IAM roles, S3 buckets) — strictly cosmetic on the brand
  side, but coordinated with a deploy.
- Git-history rewrite (#46) — purge the old personal domain reference,
  the old account ID, and any pre-rebrand artifacts from the repo's
  commit log.
- `admin@edgeposture.io` via Google Workspace, with Authenticator-app
  2FA enforced on the maintainer account.
- Transactional email integration (Postmark) for invite emails,
  password-reset shape stubs, and findings-on-schedule digests.
- Observability: structured logging on the audit pipeline, error
  tracking (Sentry or equivalent), uptime monitoring on
  `https://edgeposture.io`.

## v1.0 — First paying customer

The version where someone hands EdgePosture money. Not detailed into
tickets yet; the work below is the rough shape, not a commitment.

- Stripe billing integration (subscription + metered audit add-ons).
- Marketing site separate from the app (the current SPA is the app).
- Public signup (closed beta → open beta → general availability).
- Pricing page + an explicit free-tier definition.
- SOC 2 Type I groundwork (policies, audit-log retention, access-review
  rhythm — not the audit itself, just the prerequisites).

### v1.0 definition

EdgePosture stops being v0.x and becomes v1.0 when all five are true:

1. **One distribution path is decided and shipped** — self-host, hosted SaaS, AWS Marketplace, or hybrid. Customers can audit their own AWS account end-to-end without involving the maintainer.
2. **Bypass detection coverage is broad** — at minimum: shellshock, log4shell, SQLi, XSS, unix CVEs, generic command injection. Each with deterministic signature classification, not AI-only.
3. **Multi-region scan** — single audit run covers all AWS regions a customer uses, not just `us-east-1`.
4. **Scheduled audits** — at least weekly cron with Slack / Teams / email notification on new HIGH findings.
5. **Authentication on EdgePosture itself** — the hosted instance is no longer open. SSO via Google / Microsoft at minimum.

## Distribution model (undecided)

EdgePosture v0.1 ran only as a maintainer-hosted demo against the
maintainer's own AWS account. Making it available to audit OTHER
accounts is the highest-impact roadmap question and the choice
shapes everything in v0.2 and beyond. Possible paths under
consideration:

- **Self-hosted** — customers run their own EdgePosture instance via
  container deploy (App Runner / ECS / Fargate). Customer's IAM trust
  stays in customer's account.
- **Hosted SaaS** — EdgePosture operates a multi-tenant control plane.
  Customer creates a cross-account IAM role trusting the EdgePosture
  SaaS account. Atlas becomes multi-tenant.
- **AWS Marketplace SaaS / Container** — list EdgePosture as a
  Marketplace product so AWS handles billing + customer trust
  establishment.
- **Hybrid** — open-source the engine for self-host, run a managed
  SaaS for convenience.

No decision yet. The choice affects IAM trust model, data residency,
billing surface, multi-tenancy in Atlas, and onboarding UX.

## Out of scope (for now)

Explicitly NOT in v0.2, v0.3, or v1.0 — these are post-v1.0:

- Cloudflare / Akamai / Fastly WAF audit support (multi-cloud).
- Scheduled audits beyond the v1.0 baseline (custom cron, per-finding
  routing rules, on-call rotations).
- Multi-region scan beyond the v1.0 baseline (cross-partition,
  GovCloud, China regions).
- Audit history diff — compare two runs side-by-side.
- Authenticated scans + ZAP integration helpers.
- Drift-back-to-IaC export (Terraform / CloudFormation / CDK).
- Cost optimization recommendations beyond the current waste calculator.
