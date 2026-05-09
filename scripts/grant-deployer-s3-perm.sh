#!/usr/bin/env bash
# scripts/grant-deployer-s3-perm.sh
# Idempotently attaches an inline S3 policy to ruleiq-github-deployer so
# GHA can upload customer-role.yaml to the public templates bucket.
# Run ONCE after setup-public-bucket.sh; safe to re-run any time.
set -euo pipefail

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ROLE_NAME="ruleiq-github-deployer"
POLICY_NAME="RuleIQPublicTemplatesWrite"
BUCKET="ruleiq-public-templates-${ACCOUNT_ID}"

POLICY=$(jq -n --arg b "$BUCKET" '{
  Version: "2012-10-17",
  Statement: [{
    Sid:    "PutCfnTemplate",
    Effect: "Allow",
    Action: ["s3:PutObject", "s3:PutObjectAcl"],
    Resource: "arn:aws:s3:::\($b)/customer-role.yaml"
  }]
}')

aws iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "$POLICY_NAME" \
    --policy-document "$POLICY"

echo "OK. Inline policy '$POLICY_NAME' attached to role '$ROLE_NAME'."
echo "GHA can now write s3://${BUCKET}/customer-role.yaml"
