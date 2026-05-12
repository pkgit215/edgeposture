# RuleIQ — AI-powered AWS WAF audit

> **🔗 Live demo:** https://d96qfmakzi.us-east-1.awsapprunner.com/demo — see a sample audit with no AWS setup.

> **⚠️ Status: v0.1 beta — public demo only.** RuleIQ is not yet deployable into your own AWS account. The hosted instance at the demo URL is the only running deployment; it audits the maintainer's test account. Bringing RuleIQ to other accounts (self-host, hosted SaaS, AWS Marketplace, or another model) is on the [roadmap](ROADMAP.md) — the distribution path is not yet decided.

RuleIQ is a read-only auditor for AWS WAFv2. Once self-host support lands, you'll point it at an AWS account and get a plain-English report — which rules never fire, which attack-shaped requests are reaching origin despite the WAF, which rules are silently in COUNT mode, which Web ACLs are orphaned — plus a downloadable PDF you can hand to a SOC 2 / ISO 27001 / PCI auditor or fold into M&A due diligence.

## What it does

- Lists which WAF rules **never fired** in the last 30 days
- Detects **attack-shaped traffic reaching origin** despite the WAF (shellshock, log4shell, SQLi, XSS)
- Identifies rules silently in **COUNT mode** (logging, not blocking)
- Flags **orphaned Web ACLs** still incurring monthly fees
- Generates a **PDF report** you can hand to auditors
- Plain-English **remediation** per finding, with the exact AWS console nav path

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
