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

This is the policy a future self-hosted deploy will request from customer AWS accounts via a CloudFormation Quick-Create stack. **Not yet wired into the v0.1 hosted instance** — listed here so prospective users can pre-review what RuleIQ will (and explicitly will not) be able to do once self-host support ships.

Zero write permissions — RuleIQ will not modify, create, or delete anything in your account. Full template (when ready): [`cloudformation/customer-role.yaml`](cloudformation/customer-role.yaml).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RuleIQReadWAF",
      "Effect": "Allow",
      "Action": [
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "wafv2:ListRuleGroups",
        "wafv2:GetRuleGroup",
        "wafv2:GetLoggingConfiguration",
        "wafv2:ListResourcesForWebACL",
        "wafv2:ListAvailableManagedRuleGroups",
        "wafv2:DescribeManagedRuleGroup"
      ],
      "Resource": "*"
    },
    {
      "Sid": "RuleIQReadLogs",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents",
        "logs:GetLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "RuleIQReadAttachments",
      "Effect": "Allow",
      "Action": [
        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution",
        "elasticloadbalancing:DescribeLoadBalancers",
        "apigateway:GET",
        "cognito-idp:DescribeUserPool",
        "fms:GetAdminAccount",
        "fms:ListComplianceStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

## Status

Current: **v0.1 beta — public hosted demo only.** Self-host + customer-account audit support tracked in [ROADMAP.md](ROADMAP.md).

What works today: the hosted demo at the URL above, exercising every finding type (bypass / dead-rule / count-mode / conflict / orphan / FMS), the PDF export, and account-aware "smart" remediation — all against a committed test fixture, not a live customer account.

What's next: bringing RuleIQ to other accounts (self-host, hosted SaaS, AWS Marketplace, or another model — undecided), multi-region inspection, multi-cloud (Cloudflare / Fastly / Akamai), drift-to-IaC export, scheduled audits, app-level auth.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Local development setup, test commands, and deploy / release notes live in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).
