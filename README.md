# EdgePosture — AI-powered AWS WAF Audit

> **🔗 Live demo:** https://edgeposture.io/demo — see a sample audit with no AWS setup required.
> **⚠️ Status: v0.1 beta — hosted demo only.** Bringing EdgePosture to other accounts (self-hosted SaaS, AWS Marketplace) is on the [roadmap](ROADMAP.md).

Most AWS WAF deployments have rules that haven't fired in months, rules that should be blocking attacks but aren't, and rules nobody remembers writing. EdgePosture tells you which ones — in 2 minutes, not after a week of CloudWatch spelunking.

The headline finding: **attack-shaped traffic that reached your origin uninspected**. Shellshock, log4shell, SQL injection patterns that your WAF should have blocked but didn't. EdgePosture ships you a plain-English PDF showing exactly which signatures got through, on which Web ACL, with citations to the actual log entries — and a specific next action to close the gap.

Cleaning up dead rules and recovering the few dollars they cost is a bonus, not the point.

---

## Table of Contents

- [Live Demo](#live-demo)
- [What It Does](#what-it-does)
- [What It Looks Like](#what-it-looks-like)
- [IAM Role — What We Access and What We Cannot](#iam-role--what-we-access-and-what-we-cannot)
- [Current Status](#current-status)
- [Roadmap](ROADMAP.md)
- [Who Built This](#who-built-this)
- [Contributing](CONTRIBUTING.md)

---

## Live Demo

View the live demo at **https://edgeposture.io/demo** — Findings, Rules, and Methodology tabs, plus a downloadable sample PDF report. No AWS account or setup required.

---

## What It Does

- Detects **attack-shaped traffic reaching your origin** despite the WAF (shellshock, log4shell, SQLi, XSS, Unix CVEs) — the headline finding
- Flags rules silently sitting in **COUNT mode** when you probably think they're blocking
- Identifies which managed rule groups your Web ACL is **missing** for the attacks it's actually seeing
- Lists rules that **haven't fired in 30 days** — and whether they should have
- Flags **orphaned Web ACLs** (attached to nothing, still billed)
- Generates a **PDF you can hand** to auditors, a board, or a customer security review
- Plain-English **remediation** per finding with the exact AWS console navigation path

---

## What It Looks Like

![EdgePosture findings dashboard — severity badges, account-specific remediation, FMS pill](docs/screenshots/dashboard.png)
*Findings dashboard — severity badges, account-specific remediation, FMS Firewall Manager indicator.*

![PDF executive summary — high/medium/low counts and estimated monthly waste](docs/screenshots/pdf-exec-summary.png)
*PDF executive summary — ready to hand to auditors, board, or customers.*

![Connect screen — Quick-Create CloudFormation flow for the read-only IAM role](docs/screenshots/connect.png)
*Connect screen — Quick-Create CloudFormation generates the read-only IAM role in one click.*

---

## IAM Role — What We Access and What We Cannot

EdgePosture requires a **read-only cross-account IAM role** in your AWS account. It is provisioned via a CloudFormation Quick-Create stack — one click, no manual policy editing.

The role grants three narrow read-only permission sets. There are **zero write actions** in the policy by design.

### WAF Permissions
```json
{
  "Sid": "EdgePostureReadWAF",
  "Effect": "Allow",
  "Action": [
    "wafv2:ListWebACLs",           // Enumerate your Web ACLs — cannot create or delete
    "wafv2:GetWebACL",             // Read rule configurations — cannot modify
    "wafv2:ListRuleGroups",        // List rule groups — cannot modify
    "wafv2:GetRuleGroup",          // Read rule group contents — cannot modify
    "wafv2:GetLoggingConfiguration",       // Confirm logging is enabled — cannot change
    "wafv2:ListResourcesForWebACL",        // See what resources a Web ACL is attached to
    "wafv2:ListAvailableManagedRuleGroups",// Check which AWS Managed Rules exist
    "wafv2:DescribeManagedRuleGroup"       // Read managed rule group details
  ],
  "Resource": "*"
}
```

### Log Permissions
```json
{
  "Sid": "EdgePostureReadLogs",
  "Effect": "Allow",
  "Action": [
    "logs:DescribeLogGroups",   // Find WAF log groups — cannot create or delete
    "logs:DescribeLogStreams",  // List log streams — cannot modify
    "logs:FilterLogEvents",    // Query WAF traffic logs — the core audit data source
    "logs:GetLogEvents"        // Read individual log entries — cannot delete or modify
  ],
  "Resource": "*"
}
```

### Resource Attachment Permissions
```json
{
  "Sid": "EdgePostureReadAttachments",
  "Effect": "Allow",
  "Action": [
    "cloudfront:ListDistributions",           // See which CloudFront distributions exist
    "cloudfront:GetDistribution",             // Check if a WAF is attached
    "elasticloadbalancing:DescribeLoadBalancers", // Check ALB WAF attachments
    "apigateway:GET",                         // Check API Gateway WAF attachments
    "cognito-idp:DescribeUserPool",           // Check Cognito WAF attachments
    "fms:GetAdminAccount",                    // Detect Firewall Manager usage
    "fms:ListComplianceStatus"                // Read FMS compliance posture
  ],
  "Resource": "*"
}
```

### What EdgePosture **cannot** do

By construction, the policy above grants **zero write actions**. EdgePosture will never:

- Modify, create, delete, or override any WAF rule, ACL, or rule group
- Touch CloudFront / ALB / API Gateway resources beyond reading their metadata
- Read CloudTrail, Cost Explorer, billing data, or IAM users / keys
- Make any other API call not listed above

If a future feature ever requires a write action, the policy will be amended visibly in this README and audited via the GitHub PR review process before it ships.

### Trust Policy (confused-deputy protection)

The role uses a **per-tenant ExternalId** to prevent confused-deputy attacks. Each customer's role trusts only the EdgePosture host account and only with their unique ExternalId — no other tenant can trigger an AssumeRole against your account.

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::EDGEPOSTURE_HOST_ACCOUNT:role/edgeposture-apprunner-instance"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "<your-unique-per-tenant-id>"
    }
  }
}
```

For full IAM setup details see [docs/iam-setup.md](docs/iam-setup.md).

---

## Current Status

**v0.1 beta — public hosted demo only.**

What works today:
- Hosted demo at the URL above, exercising every finding type (bypass / dead-rule / count-mode / conflict / orphan / FMS)
- PDF export with executive summary
- Account-aware "smart" remediation — all against a committed test fixture

What's next (see [ROADMAP.md](ROADMAP.md)):
- Multi-tenant SaaS — onboard your own AWS account
- Self-hosted deployment option
- AWS Marketplace listing
- Multi-region inspection
- Scheduled audits and drift-to-IaC export
- Multi-cloud (Cloudflare / Fastly / Akamai)

---

## Who Built This

EdgePosture is built by a senior AWS infrastructure engineer who previously owned the **edge and WAF solution at AWS**, responsible for the reference architecture and tooling used across AWS's own edge services. Current work includes independent AWS WAF consulting engagements with enterprise clients.

The tool exists because the same gaps — rules silently in COUNT mode, attack signatures reaching origin, orphaned ACLs, missing managed rule groups — show up in nearly every WAF deployment we audit, regardless of company size. EdgePosture automates the first two hours of every engagement.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Local development setup, test commands, and deploy/release notes live in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
