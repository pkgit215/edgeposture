# RuleIQ — AI-powered AWS WAF audit

> **🔗 Live demo:** https://d96qfmakzi.us-east-1.awsapprunner.com/demo — see a sample audit without setting up AWS. To run an audit against your own account, click "Set up an audit →" on the demo page.

RuleIQ is a read-only auditor for AWS WAFv2. Point it at an account and 60 seconds later you get a plain-English report — which rules never fire, which attack-shaped requests are reaching origin despite the WAF, which rules are silently in COUNT mode, which Web ACLs are orphaned — plus a downloadable PDF you can hand to a SOC 2 / ISO 27001 / PCI auditor or fold straight into M&A due diligence.

## What it does

- Lists which WAF rules **never fired** in the last 30 days
- Detects **attack-shaped traffic reaching origin** despite the WAF (shellshock, log4shell, SQLi, XSS)
- Identifies rules silently in **COUNT mode** (logging, not blocking)
- Flags **orphaned Web ACLs** still incurring monthly fees
- Generates a **PDF report** you can hand to auditors
- Plain-English **remediation** per finding, with the exact AWS console nav path

## How it works

1. You create a **read-only IAM role** in your AWS account and paste the Role ARN into RuleIQ.
2. RuleIQ assumes the role via STS — **temporary session tokens only, never stores keys**.
3. It reads your WAF rules, Web ACL attachments, and **30 days of CloudWatch log samples**.
4. Deterministic detectors classify findings; **GPT-4o** provides the plain-English explanation per rule.
5. Results persist in MongoDB; the **PDF report** is rendered on demand.

## Try it

- **Live demo (no AWS setup):** https://d96qfmakzi.us-east-1.awsapprunner.com/demo
- **Run against your own AWS account:** see [DEMO.md](DEMO.md) for the 3-step quickstart.
- **Scoring methodology:** click the **Methodology** tab inside any audit (or page 13 of the demo PDF) for how severity, confidence, and the $/month figure are derived.

## IAM role required (read-only)

Customers grant RuleIQ access via a CloudFormation Quick-Create stack. The role has **zero write permissions** — RuleIQ cannot modify, create, or delete anything in your account.

Minimum required actions (full template at [`cloudformation/customer-role.yaml`](cloudformation/customer-role.yaml)):

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

The role's **trust policy** is restricted to the RuleIQ service AWS account and an ExternalId derived from your account — both are emitted by the Quick-Create stack, so customers never paste raw IDs.

## Status

**Current: v0.1 (Proof of Concept).** Hosted demo only — RuleIQ is **not yet self-deployable**. The maintainer-hosted instance at https://d96qfmakzi.us-east-1.awsapprunner.com is the only running environment during the PoC phase. Self-hosting support is on the roadmap.

What works today: live audits against a real AWS account, full finding catalogue (bypass / dead-rule / count-mode / conflict / orphan / FMS), PDF export, account-aware "smart" remediation.

What's coming: see [ROADMAP.md](ROADMAP.md) for the trajectory — multi-region inspection, multi-cloud (Cloudflare / Fastly / Akamai), drift-to-IaC export, scheduled audits, app-level auth.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Local development setup, test commands, and deploy / release notes live in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).
