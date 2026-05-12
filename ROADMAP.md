# EdgePosture — Roadmap

One-line-per-phase status board. Open backlog lives in GitHub Issues.

## v1.0 definition

EdgePosture stops being v0.x and becomes v1.0 when all five are true:

1. **One distribution path is decided and shipped** — self-host, hosted SaaS, AWS Marketplace, or hybrid. Customers can audit their own AWS account end-to-end without involving the maintainer.
2. **Bypass detection coverage is broad** — at minimum: shellshock, log4shell, SQLi, XSS, unix CVEs, generic command injection. Each with deterministic signature classification, not AI-only.
3. **Multi-region scan** — single audit run covers all AWS regions a customer uses, not just us-east-1.
4. **Scheduled audits** — at least weekly cron with Slack / Teams / email notification on new HIGH findings.
5. **Authentication on EdgePosture itself** — the hosted instance is no longer open. SSO via Google / Microsoft at minimum.

Cost optimization, IaC export, multi-cloud, and authenticated scans are post-v1.0.

## Distribution model (undecided)

EdgePosture v0.1 runs only as a maintainer-hosted demo against the maintainer's own AWS account. Making it available to audit OTHER accounts is the highest-impact roadmap question. Possible paths under consideration:

- **Self-hosted** — customers run their own EdgePosture instance via container deploy (App Runner / ECS / Fargate). Customer's IAM trust stays in customer's account.
- **Hosted SaaS** — EdgePosture operates a multi-tenant control plane. Customer creates a cross-account IAM role trusting the EdgePosture SaaS account. Atlas becomes multi-tenant.
- **AWS Marketplace SaaS / Container** — list EdgePosture as a Marketplace product so AWS handles billing + customer trust establishment.
- **Hybrid** — open source the engine for self-host, run a managed SaaS for convenience.

No decision yet. The choice affects IAM trust model, data residency, billing surface, multi-tenancy in Atlas, and onboarding UX.

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
- Domain acquisition — `edgeposture.io` is squatter-parked on GoDaddy (broker fee ~£78 + likely $400–2,000 sale price); `.io` and `.ai` also taken. Decision before any public sharing (`area:deployment`, priority p2).

## Backlog

- Authenticated scans + ZAP integration helpers (`area:integrations`).
- Scheduled audits — weekly cron (`area:integrations`).
- Multi-region audit scan (`area:backend`).
- App authentication — login on EdgePosture itself (`area:backend`, `area:frontend`).
- Audit history diff — compare two runs (`area:frontend`, `area:backend`).
- Migration plan — App Runner → ECS Express Mode (`area:deployment`).
- Multi-cloud — Cloudflare, Akamai, Fastly WAF audits (`area:multicloud`).
- Drift-back-to-IaC export — Terraform / CloudFormation / CDK (`area:backend`).
- "Email this PDF to my auditor" button — SES (`area:frontend`, `area:backend`).
- `?print=true` query-string for browser-printable Results view (`area:frontend`).
- `/api/version` endpoint with git SHA + build timestamp (`area:backend`).
