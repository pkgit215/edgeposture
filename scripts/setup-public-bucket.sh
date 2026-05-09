#!/usr/bin/env bash
# scripts/setup-public-bucket.sh
# Creates a public-read S3 bucket that hosts cloudformation/customer-role.yaml
# so the AWS console Quick-Create URL can fetch it unauthenticated.
# Run ONCE in CloudShell or any environment with admin AWS creds for the
# RuleIQ App Runner account.
set -euo pipefail

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET="ruleiq-public-templates-${ACCOUNT_ID}"
REGION="us-east-1"

echo "Account: $ACCOUNT_ID"
echo "Bucket:  $BUCKET"
echo "Region:  $REGION"

# Create bucket (idempotent — succeeds if missing, errors silently if owned by us)
aws s3api create-bucket \
    --bucket "$BUCKET" \
    --region "$REGION" 2>/dev/null || true

# Allow public access at the account/bucket level
aws s3api put-public-access-block \
    --bucket "$BUCKET" \
    --public-access-block-configuration \
        "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"

# Public-read bucket policy
POLICY=$(jq -n --arg b "$BUCKET" '{
  Version: "2012-10-17",
  Statement: [{
    Sid:    "PublicRead",
    Effect: "Allow",
    Principal: "*",
    Action: "s3:GetObject",
    Resource: "arn:aws:s3:::\($b)/*"
  }]
}')
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$POLICY"

cat <<EOF

OK. Bucket is ready for public reads:
    https://${BUCKET}.s3.${REGION}.amazonaws.com/

Next steps:
    1. Re-run scripts/grant-deployer-s3-perm.sh once so GHA can write here.
    2. Push Phase 2 code; the workflow will sync customer-role.yaml on deploy.
EOF
