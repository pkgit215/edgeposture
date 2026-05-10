#!/usr/bin/env bash
# Bootstrap the EXTERNAL_ID_SECRET in AWS Secrets Manager and grant the
# App Runner instance role read access. Run this ONCE per AWS account.
#
# This script is idempotent: running it again on an existing secret will
# print the existing ARN without touching the value (rotating the secret
# invalidates every customer's existing IAM trust policy — see
# docs/known_issues.md before you do that).
#
# Required: aws CLI authenticated as a principal with permission to:
#   - secretsmanager:CreateSecret / DescribeSecret
#   - iam:PutRolePolicy on the instance role
#
# Usage:  bash scripts/setup-external-id-secret.sh
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID="${AWS_ACCOUNT_ID:-371126261144}"
SECRET_NAME="ruleiq/external-id-secret"
INSTANCE_ROLE="ruleiq-apprunner-instance"
INLINE_POLICY_NAME="AllowReadExternalIdSecret"

SECRET_ARN_PREFIX="arn:aws:secretsmanager:${REGION}:${ACCOUNT_ID}:secret:${SECRET_NAME}"

echo "==> Region:       $REGION"
echo "==> Account:      ***...${ACCOUNT_ID: -4}"
echo "==> Secret name:  $SECRET_NAME"
echo "==> Role:         $INSTANCE_ROLE"
echo

# 1) Create-or-keep the secret.
if aws secretsmanager describe-secret \
    --region "$REGION" \
    --secret-id "$SECRET_NAME" >/dev/null 2>&1; then
  echo "==> Secret already exists — leaving the value untouched."
  EXISTING_ARN=$(aws secretsmanager describe-secret \
      --region "$REGION" \
      --secret-id "$SECRET_NAME" \
      --query 'ARN' --output text)
  echo "    ARN: $EXISTING_ARN"
else
  echo "==> Generating a 64-hex-char random value and creating the secret..."
  SECRET_VALUE=$(python3 -c "import secrets;print(secrets.token_hex(32))")
  CREATE_OUT=$(aws secretsmanager create-secret \
      --region "$REGION" \
      --name "$SECRET_NAME" \
      --description "RuleIQ HMAC key for deriving deterministic ExternalIds per AWS account ID. Rotation invalidates every customer's IAM trust policy — see docs/known_issues.md." \
      --secret-string "$SECRET_VALUE")
  EXISTING_ARN=$(echo "$CREATE_OUT" | python3 -c "import json,sys;print(json.load(sys.stdin)['ARN'])")
  echo "    Created: $EXISTING_ARN"
  unset SECRET_VALUE
fi

# 2) Grant the instance role permission to read the secret. The SDK on App
#    Runner uses the instance role (boto3 default chain) to GetSecretValue.
echo
echo "==> Attaching inline policy '$INLINE_POLICY_NAME' to $INSTANCE_ROLE..."
cat > /tmp/external-id-secret-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
      "Resource": "${SECRET_ARN_PREFIX}*"
    }
  ]
}
JSON

aws iam put-role-policy \
    --role-name "$INSTANCE_ROLE" \
    --policy-name "$INLINE_POLICY_NAME" \
    --policy-document file:///tmp/external-id-secret-policy.json

rm -f /tmp/external-id-secret-policy.json
echo "    Done."

echo
echo "Bootstrap complete."
echo
echo "Next: push to main (or re-run the deploy workflow). The GHA pipeline"
echo "will inject EXTERNAL_ID_SECRET into the App Runner service via"
echo "RuntimeEnvironmentSecrets and trigger a redeploy."
