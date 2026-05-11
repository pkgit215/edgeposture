# RuleIQ — Live Demo

**🔗 Live sample audit (no AWS setup):** https://d96qfmakzi.us-east-1.awsapprunner.com/demo

**🔗 Run against your own AWS account:** https://d96qfmakzi.us-east-1.awsapprunner.com

## See a sample audit in 10 seconds

Open the `/demo` URL above. It renders a fully-populated audit using a
committed fixture — every finding type (`bypass_candidate`, `dead_rule`,
`conflict`, `quick_win`, `fms_review`), every Remediation block, the
Methodology tab, and a downloadable PDF report. No IAM role required.
Click "Set up an audit →" on the banner to graduate to a real audit
against your own account.

## 3-step quickstart (real audit)

1. **Visit the root URL above** (no `/demo`).
2. **Paste your AWS Account ID** (12 digits, any valid format).
3. **Follow the displayed instructions** to create the read-only IAM role
   in your AWS account, paste the Role ARN back into the form, and click
   **Run Audit**.

## Expected output

A PDF audit report ready in approximately 2 minutes. The PDF leads with
security posture (high-severity findings, bypass candidates, stranded
rules), then operational hygiene (orphans, dead rules, COUNT-mode rules
worth promoting), then cost optimisation. Every finding ships with a
canned Remediation block — Suggested actions, Verify by, and a universal
disclaimer.

## Safety guarantees

RuleIQ is read-only — it cannot create, modify, or delete any rule in
your account. All AWS calls use STS AssumeRole with session tokens only.
No keys are stored. Source code is available at
[github.com/pkgit215/ruleiq](https://github.com/pkgit215/ruleiq); the
IAM role definition (`cloudformation/customer-role.yaml`) is
public so you can audit every permission RuleIQ requests before granting
it.

## More

- See the [Setup](./README.md#phase-2--running-a-real-audit) section of
  the README for the full onboarding sequence (CFN Quick-Create or
  bash scripts).
- See the **Methodology** tab inside the audit report — or its mirror
  appendix in the PDF — for how severity (HIGH / MEDIUM / LOW),
  severity score (0–10), confidence (0–100%) and evidence types are
  derived.
