# RuleIQ — Roadmap

One-line-per-phase status board. Open backlog lives in GitHub Issues.

## Shipped

- **Phase 0** — POC: AI pipeline (Pass 1 explain + Pass 2 findings), FastAPI scaffold, ECR + App Runner deploy via GHA.
- **Phase 1** — MongoDB persistence: audits, rules, findings collections.
- **Phase 2** — AWS WAFv2 ingestion: list_web_acls + get_web_acl_rules + STS AssumeRole with ExternalId.
- **Phase 3** — React SPA: Connect → Audit → Results flow. PDF download.
- **Phase 4** — Demo mode: bundled fixtures, FMS guardrails, AI Pass 1+2 LangChain wiring.
- **Phase 5** — Severity scoring, orphan ACL detection, Pass 3 bypass sampler over CloudWatch ALLOW logs, waste-cost calc.
- **Phase 5.2** — Regional/CloudFront scope split, `attachment_lookup` structured logging, debug endpoint.
- **Phase 5.2.1** — CloudFront `us-east-1` region pin, frontend timestamp parser.
- **Phase 5.2.2** — Server-side ISO-8601 `Z` suffix, stranded-rule reclassifier, friendly resource names (CloudFront alias, ALB DNSName, API GW name).
- **Phase 5.3** — Canned remediation per finding type, three deterministic COUNT-mode findings, `RuleActionOverrides` extraction, value reframing (security-first cover & UI).
- **Phase 5.3.1** — Wire-up fix: flat-key remediation on every persisted finding, bypass affected_rules backfill, UTC Z regression test, health phase = 5.3.
- **Phase 5.3.2** — Bypass `affected_rules` invariant + per-ACL tagging, `quick_win` copy dispatch (unused vs duplicate-pair), dead_rule severity rubric (HIGH only when corroborated), conflict regression fix, Impact field on every finding, Methodology tab + tooltips + PDF appendix.
- **Phase A.5** — GitHub hygiene: issue templates, label set, seed scripts, this roadmap.

## Active

- See GitHub Issues with `priority:p1` — picked off in order.

## Next

- Signature-class correlation for dead_rule severity escalation (`area:scoring`).
- URL-encoded payload decoding in suspicion scorer (`area:scoring`).
- CSV export of Web ACL attachment inventory (`area:frontend`, `area:backend`).
- UI provenance badge for log-sample evidence (`area:frontend`, `area:methodology`).
- Slack / Teams webhook on HIGH findings (`area:integrations`).

## Backlog

- Authenticated scans + ZAP integration helpers (`area:integrations`).
- Scheduled audits — weekly cron (`area:integrations`).
- Multi-region audit scan (`area:backend`).
- App authentication — login on RuleIQ itself (`area:backend`, `area:frontend`).
- Audit history diff — compare two runs (`area:frontend`, `area:backend`).
- Migration plan — App Runner → ECS Express Mode (`area:deployment`).
- Multi-cloud — Cloudflare, Akamai, Fastly WAF audits (`area:multicloud`).
- Drift-back-to-IaC export — Terraform / CloudFormation / CDK (`area:backend`).
- "Email this PDF to my auditor" button — SES (`area:frontend`, `area:backend`).
- `?print=true` query-string for browser-printable Results view (`area:frontend`).
- `/api/version` endpoint with git SHA + build timestamp (`area:backend`).
- Domain acquisition — `ruleiq.com` via GoDaddy or broker, ceiling $1.5k (`area:deployment`).
