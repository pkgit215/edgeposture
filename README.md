# RuleIQ — AI-powered AWS WAF audit

> **🔗 Live demo:** https://d96qfmakzi.us-east-1.awsapprunner.com/demo — see a sample audit with no AWS setup.

> **⚠️ Status: v0.1 beta — public demo only.** RuleIQ is not yet deployable into your own AWS account. The hosted instance at the demo URL is the only running deployment; it audits the maintainer's test account. Bringing RuleIQ to other accounts (self-host, hosted SaaS, AWS Marketplace, or another model) is on the [roadmap](ROADMAP.md) — the distribution path is not yet decided.

Most AWS WAF deployments have rules that haven't fired in months, rules that should be blocking attacks but aren't, and rules nobody remembers writing. RuleIQ tells you which ones — in 2 minutes, not after a week of CloudWatch spelunking.

The headline finding: **attack-shaped traffic that reached your origin uninspected**. Shellshock, log4shell, SQL injection patterns that your WAF should have blocked but didn't. RuleIQ ships you a plain-English PDF showing exactly which signatures got through, on which Web ACL, with citations to the actual log entries — and a specific next action to close the gap.

Cleaning up dead rules and recovering the few dollars they cost is a bonus, not the point.

## What it looks like

![RuleIQ findings dashboard — severity badges, account-specific remediation, FMS pill](docs/screenshots/dashboard.png)
*Findings dashboard — severity badges, account-specific remediation, FMS Firewall Manager indicator.*

![PDF executive summary — high/medium/low counts and estimated monthly waste](docs/screenshots/pdf-exec-summary.png)
*PDF executive summary — handed to auditors, board, customers.*

![Connect screen — Quick-Create CloudFormation flow for the read-only IAM role](docs/screenshots/connect.png)
*Connect screen (future self-host) — Quick-Create CloudFormation generates the read-only IAM role in one click.*

## What it does

- Detects **attack-shaped traffic reaching your origin** despite the WAF (shellshock, log4shell, SQLi, XSS, unix CVEs) — the headline finding
- Flags rules silently sitting in **COUNT mode** when you probably think they're blocking
- Identifies which managed rule groups your Web ACL is **missing** for the attacks it's seeing
- Lists rules that **haven't fired in 30 days** — and whether they should have
- Flags **orphaned Web ACLs** (attached to nothing, still billed)
- Generates a **PDF you can hand** to auditors, board, or a customer security review
- Plain-English **remediation** per finding with the exact AWS console nav path

## What you can do today

- View the live demo at https://d96qfmakzi.us-east-1.awsapprunner.com/demo to see a sample audit — Findings, Rules, Methodology tabs, plus a downloadable sample PDF report. **No AWS setup required.**
- That is the only end-to-end flow available in v0.1. The self-serve "audit your own AWS account" flow is not yet wired in; the hosted demo only trusts the maintainer's test account.

## IAM policy (reference only)

For the IAM role policies and AWS setup commands a future self-hosted deploy will require, see [docs/iam-setup.md](docs/iam-setup.md).

## Status

Current: **v0.1 beta — public hosted demo only.** Self-host + customer-account audit support tracked in [ROADMAP.md](ROADMAP.md).

What works today: the hosted demo at the URL above, exercising every finding type (bypass / dead-rule / count-mode / conflict / orphan / FMS), the PDF export, and account-aware "smart" remediation — all against a committed test fixture, not a live customer account.

What's next: bringing RuleIQ to other accounts (self-host, hosted SaaS, AWS Marketplace, or another model — undecided), multi-region inspection, multi-cloud (Cloudflare / Fastly / Akamai), drift-to-IaC export, scheduled audits, app-level auth.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Local development setup, test commands, and deploy / release notes live in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).
