# RuleIQ IAM setup (operational)

Cross-link: [README](../README.md) · [DEVELOPMENT.md](DEVELOPMENT.md)

## Why this lives here

This is operator-flavoured material for the future self-hosted distribution path — what a RuleIQ self-host operator (or the future hosted-SaaS control plane) will do to provision the read-only audit role inside a customer AWS account. It is **not** customer-facing onboarding copy and is **not** wired up in v0.1. The customer-facing README intentionally keeps to value-prop + screenshots + status; everything below moves here so the README stays a 100-line marketing page rather than an operator runbook.

## What customers will be granting (read-only IAM policy)

This is the policy a future self-hosted deploy will request from customer AWS accounts via a CloudFormation Quick-Create stack. Zero write permissions — RuleIQ will not modify, create, or delete anything in any customer account. Authoritative template lives at [`cloudformation/customer-role.yaml`](../cloudformation/customer-role.yaml).

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

## Trust policy (RuleIQAuditRole)

The `RuleIQAuditRole` in the customer AWS account trusts the RuleIQ host AWS account (specifically: the App Runner instance role) via a per-tenant `ExternalId`. The ExternalId is HMAC-derived from `EXTERNAL_ID_SECRET` (kept in Secrets Manager on the RuleIQ host side) and the customer's AWS account number — stable across page reloads, unique per customer.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/ruleiq-apprunner-instance"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "ruleiq-tenant-derived-value"
        }
      }
    }
  ]
}
```

`123456789012` above is the AWS-reserved test account ID — replace with the actual RuleIQ host account when self-host ships. The customer-facing CloudFormation template substitutes this at apply-time via a Quick-Create parameter.

## Operational commands (future self-host)

Once self-host ships, an operator provisioning a per-tenant audit role from a maintenance shell would run something like:

```bash
# 1. Materialise the customer audit role from the canonical template.
aws cloudformation create-stack \
  --stack-name ruleiq-audit-role \
  --template-url "https://ruleiq-public-templates-${RULEIQ_HOST_ACCOUNT_ID}.s3.${AWS_REGION}.amazonaws.com/customer-role.yaml" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
      ParameterKey=RuleIQHostAccountId,ParameterValue="${RULEIQ_HOST_ACCOUNT_ID}" \
      ParameterKey=ExternalId,ParameterValue="${PER_TENANT_EXTERNAL_ID}"

# 2. If you need to attach an additional inline policy (rare — the CFN
#    template already grants everything the auditor needs), the operator
#    equivalent is:
aws iam put-role-policy \
  --role-name RuleIQAuditRole \
  --policy-name RuleIQAuditRoleExtension \
  --policy-document file://extra-permissions.json

# 3. Force a refresh of the trust policy on the auditor role — e.g. when
#    the RuleIQ host account ID rotates:
aws iam update-assume-role-policy \
  --role-name RuleIQAuditRole \
  --policy-document file://trust-policy.json
```

### IAM propagation timing

Newly-created IAM roles can take **30–60 seconds** to become assumable by `sts:AssumeRole` across regions. If a fresh stack creation is followed by an immediate audit kick-off, the first `AssumeRole` call may return `AccessDenied` even though the role is correctly defined. Re-try with exponential backoff (RuleIQ retries up to 6 times, capping at 30s).

## What this policy **cannot** do

By construction, the policy above grants **zero write actions**. RuleIQ cannot:

- Modify, create, delete, or override any WAF rule, ACL, or rule group
- Touch CloudFront / ALB / API Gateway resources beyond reading their metadata
- Read CloudTrail, Cost Explorer, billing, or IAM users / keys
- Make any other API call against the customer account

If a future feature ever requires a write action, the policy must be amended visibly here — and audited via the GitHub PR review process before it ships.
