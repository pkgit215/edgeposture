#!/usr/bin/env bash
# scripts/teardown-test-waf.sh
# Removes the disposable WAF created by setup-test-waf.sh and the customer
# CFN stack. Safe to re-run.
set -euo pipefail

REGION="${REGION:-us-east-1}"
SCOPE="REGIONAL"
ACL_NAME="ruleiq-test-acl"
IPSET_NAME="ruleiq-test-blocklist"
LOG_GROUP="aws-waf-logs-ruleiq-test"
STACK_NAME="RuleIQAuditRole"

ACL_INFO=$(aws wafv2 list-web-acls --scope "$SCOPE" --region "$REGION" \
  --query "WebACLs[?Name=='$ACL_NAME']|[0]" --output json)
if [[ "$(echo "$ACL_INFO" | jq -r '.Id // empty')" ]]; then
  ACL_ID=$(echo "$ACL_INFO" | jq -r '.Id')
  ACL_LOCK=$(echo "$ACL_INFO" | jq -r '.LockToken')
  ACL_ARN=$(echo "$ACL_INFO" | jq -r '.ARN')
  echo "Disabling WAF logging..."
  aws wafv2 delete-logging-configuration --resource-arn "$ACL_ARN" --region "$REGION" 2>/dev/null || true
  echo "Deleting Web ACL $ACL_NAME..."
  aws wafv2 delete-web-acl --name "$ACL_NAME" --scope "$SCOPE" --id "$ACL_ID" --lock-token "$ACL_LOCK" --region "$REGION"
fi

IPSET_INFO=$(aws wafv2 list-ip-sets --scope "$SCOPE" --region "$REGION" \
  --query "IPSets[?Name=='$IPSET_NAME']|[0]" --output json)
if [[ "$(echo "$IPSET_INFO" | jq -r '.Id // empty')" ]]; then
  ID=$(echo "$IPSET_INFO" | jq -r '.Id')
  LOCK=$(echo "$IPSET_INFO" | jq -r '.LockToken')
  echo "Deleting IPSet $IPSET_NAME..."
  aws wafv2 delete-ip-set --name "$IPSET_NAME" --scope "$SCOPE" --id "$ID" --lock-token "$LOCK" --region "$REGION"
fi

echo "Deleting log group $LOG_GROUP..."
aws logs delete-log-group --log-group-name "$LOG_GROUP" --region "$REGION" 2>/dev/null || true

echo "Deleting CFN stack $STACK_NAME..."
aws cloudformation delete-stack --stack-name "$STACK_NAME" --region "$REGION" 2>/dev/null || true

echo "Done."
