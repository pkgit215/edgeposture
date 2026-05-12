# EdgePosture — Live Demo

> **⚠️ Status: v0.1 beta — public demo only.** The self-serve "audit your own AWS account" flow is **not functional** in v0.1. The hosted instance only trusts the maintainer's test account.

**🔗 Live sample audit (no AWS setup):** https://d96qfmakzi.us-east-1.awsapprunner.com/demo

## What you can do in the demo

The `/demo` URL above is the only end-to-end flow available today. It renders a fully populated audit against a committed test fixture — every finding type (`bypass_candidate`, `dead_rule`, `conflict`, `quick_win`, `fms_review`, `count_mode_with_hits`, `count_mode_high_volume`, `managed_rule_override_count`, `orphaned_web_acl`), every Remediation block, the Methodology tab, and a downloadable PDF report.

## Walkthrough

1. **Open https://d96qfmakzi.us-east-1.awsapprunner.com/demo** — no IAM role, no Account ID, no AWS console needed.
2. **Explore the tabs** — Findings (severity-sorted with remediation expansions), Rules (all 52 rules across 4 Web ACLs with hit counts), and Methodology (severity / confidence / waste-cost methodology). Click **Download Report** for the sample PDF.
3. **There is no step 3.** The "audit your own AWS account" flow is not available in v0.1 — see the status callout above. Future support for auditing your own AWS account is on the roadmap — exact distribution model (self-host, SaaS, Marketplace, or other) is undecided. See [ROADMAP.md](ROADMAP.md#distribution-model-undecided) for the options under consideration.

## Safety / read-only context

EdgePosture is designed to be a **read-only auditor**. The IAM policy it will request from customer accounts (see [README.md](README.md#iam-policy-reference-only)) contains zero write permissions — EdgePosture cannot modify, create, or delete WAF rules, ACLs, or any other AWS resource. The live demo does not touch any customer account.
