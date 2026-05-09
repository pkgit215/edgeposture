#!/usr/bin/env bash
# scripts/setup-test-waf.sh
# Creates a disposable WAFv2 setup so RuleIQ has something real to audit.
# Resources created:
#   - IPSet  ruleiq-test-blocklist
#   - LogGroup aws-waf-logs-ruleiq-test (7-day retention)
#   - WebACL ruleiq-test-acl (REGIONAL, default ALLOW)
#       1. BlockBadIPs        BLOCK   IPSetReferenceStatement
#       2. RateLimitGlobal    BLOCK   RateBasedStatement (1000 / IP)
#       3. BlockAdminPath     BLOCK   ByteMatchStatement /admin/
#       4. LegacyDeadRule     BLOCK   ByteMatchStatement on stale header
#   - Logging configuration on the Web ACL → CloudWatch
#   - 5,000 fake WAF log events seeded across rules
#
# Required env:
#   RULEIQ_URL   — your live App Runner URL, e.g. https://abc123.us-east-1.awsapprunner.com
#
# Run ONCE in CloudShell (or any us-east-1 admin shell). Idempotent for the
# create steps; the seeded events are always appended.
set -euo pipefail

REGION="${REGION:-us-east-1}"
SCOPE="REGIONAL"
ACL_NAME="ruleiq-test-acl"
IPSET_NAME="ruleiq-test-blocklist"
LOG_GROUP="aws-waf-logs-ruleiq-test"
LOG_STREAM="ruleiq-test-stream"

if [[ -z "${RULEIQ_URL:-}" ]]; then
  echo "ERROR: set RULEIQ_URL=https://<your-app-runner>" >&2
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Account: $ACCOUNT_ID  Region: $REGION"

# 1) IPSet ---------------------------------------------------------------------
IPSET_ID=$(aws wafv2 list-ip-sets --scope "$SCOPE" --region "$REGION" \
  --query "IPSets[?Name=='$IPSET_NAME'].Id | [0]" --output text)
if [[ "$IPSET_ID" == "None" || -z "$IPSET_ID" ]]; then
  echo "Creating IPSet $IPSET_NAME..."
  CREATE_OUT=$(aws wafv2 create-ip-set \
    --name "$IPSET_NAME" \
    --scope "$SCOPE" \
    --region "$REGION" \
    --ip-address-version IPV4 \
    --addresses "203.0.113.5/32" "198.51.100.10/32" "192.0.2.20/32")
  IPSET_ID=$(echo "$CREATE_OUT" | jq -r '.Summary.Id')
fi
IPSET_ARN=$(aws wafv2 list-ip-sets --scope "$SCOPE" --region "$REGION" \
  --query "IPSets[?Name=='$IPSET_NAME'].ARN | [0]" --output text)
echo "IPSet ARN: $IPSET_ARN"

# 2) LogGroup ------------------------------------------------------------------
if ! aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP" --region "$REGION" \
    --query "logGroups[?logGroupName=='$LOG_GROUP']" --output text | grep -q "$LOG_GROUP"; then
  aws logs create-log-group --log-group-name "$LOG_GROUP" --region "$REGION"
  aws logs put-retention-policy --log-group-name "$LOG_GROUP" --retention-in-days 7 --region "$REGION"
fi
LOG_GROUP_ARN="arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP}:*"
echo "LogGroup: $LOG_GROUP"

# 3) Web ACL -------------------------------------------------------------------
RULES_JSON=$(cat <<EOF
[
  {
    "Name": "BlockBadIPs",
    "Priority": 1,
    "Action": {"Block": {}},
    "Statement": {"IPSetReferenceStatement": {"ARN": "$IPSET_ARN"}},
    "VisibilityConfig": {"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "BlockBadIPs"}
  },
  {
    "Name": "RateLimitGlobal",
    "Priority": 2,
    "Action": {"Block": {}},
    "Statement": {"RateBasedStatement": {"Limit": 1000, "AggregateKeyType": "IP"}},
    "VisibilityConfig": {"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "RateLimitGlobal"}
  },
  {
    "Name": "BlockAdminPath",
    "Priority": 3,
    "Action": {"Block": {}},
    "Statement": {"ByteMatchStatement": {"SearchString": "/admin/", "FieldToMatch": {"UriPath": {}}, "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}], "PositionalConstraint": "STARTS_WITH"}},
    "VisibilityConfig": {"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "BlockAdminPath"}
  },
  {
    "Name": "LegacyDeadRule",
    "Priority": 4,
    "Action": {"Block": {}},
    "Statement": {"ByteMatchStatement": {"SearchString": "legacy", "FieldToMatch": {"SingleHeader": {"Name": "x-old-header"}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}], "PositionalConstraint": "EXACTLY"}},
    "VisibilityConfig": {"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "LegacyDeadRule"}
  }
]
EOF
)

ACL_ID=$(aws wafv2 list-web-acls --scope "$SCOPE" --region "$REGION" \
  --query "WebACLs[?Name=='$ACL_NAME'].Id | [0]" --output text)

if [[ "$ACL_ID" == "None" || -z "$ACL_ID" ]]; then
  echo "Creating Web ACL $ACL_NAME..."
  CREATE_OUT=$(aws wafv2 create-web-acl \
    --name "$ACL_NAME" \
    --scope "$SCOPE" \
    --region "$REGION" \
    --default-action '{"Allow": {}}' \
    --visibility-config "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=ruleiq-test-acl" \
    --rules "$RULES_JSON")
  ACL_ID=$(echo "$CREATE_OUT" | jq -r '.Summary.Id')
fi

ACL_ARN=$(aws wafv2 list-web-acls --scope "$SCOPE" --region "$REGION" \
  --query "WebACLs[?Name=='$ACL_NAME'].ARN | [0]" --output text)
echo "Web ACL ARN: $ACL_ARN"

# 4) Logging configuration -----------------------------------------------------
echo "Configuring WAF logging → $LOG_GROUP..."
aws wafv2 put-logging-configuration \
  --logging-configuration "{\"ResourceArn\": \"$ACL_ARN\", \"LogDestinationConfigs\": [\"${LOG_GROUP_ARN%:*}\"]}" \
  --region "$REGION" >/dev/null || true

# 5) Seed log stream + 5000 fake events ---------------------------------------
aws logs create-log-stream --log-group-name "$LOG_GROUP" --log-stream-name "$LOG_STREAM" --region "$REGION" 2>/dev/null || true

NOW_MS=$(($(date +%s) * 1000))
TMP=$(mktemp)

# Distribution: BlockBadIPs ~2000, RateLimitGlobal ~1500, BlockAdminPath ~1500, LegacyDeadRule 0
python3 - <<PY > "$TMP"
import json, random, time
now_ms = int(time.time() * 1000)
events = []
def push(rule, action, n):
    for i in range(n):
        ts = now_ms - random.randint(0, 30 * 86400 * 1000)
        msg = {
            "timestamp": ts,
            "formatVersion": 1,
            "webaclId": "$ACL_ARN",
            "terminatingRuleId": rule,
            "action": action,
            "httpRequest": {
                "uri": random.choice(["/", "/api", "/admin/users", "/login", "/cart"]),
                "clientIp": random.choice(["203.0.113.5", "198.51.100.10", "192.0.2.20"]),
                "country": "US",
            },
            "ruleGroupList": [],
        }
        events.append({"timestamp": ts, "message": json.dumps(msg)})
push("BlockBadIPs", "BLOCK", 2000)
push("RateLimitGlobal", "BLOCK", 1500)
push("BlockAdminPath", "BLOCK", 1500)
# LegacyDeadRule: zero events
events.sort(key=lambda e: e["timestamp"])
for chunk_start in range(0, len(events), 1000):
    print(json.dumps(events[chunk_start:chunk_start + 1000]))
PY

while IFS= read -r CHUNK; do
  aws logs put-log-events \
    --log-group-name "$LOG_GROUP" \
    --log-stream-name "$LOG_STREAM" \
    --region "$REGION" \
    --log-events "$CHUNK" >/dev/null
done < "$TMP"
rm -f "$TMP"
echo "Seeded ~5000 events across 3 firing rules; LegacyDeadRule intentionally zero."

# 6) Pull setup-info from the live RuleIQ app ---------------------------------
echo
echo "Fetching Quick-Create URL from $RULEIQ_URL/api/setup-info..."
SETUP_INFO=$(curl -fsS "$RULEIQ_URL/api/setup-info")
EXTERNAL_ID=$(echo "$SETUP_INFO" | jq -r '.external_id')
QUICK_CREATE=$(echo "$SETUP_INFO" | jq -r '.cfn_quick_create_url')

cat <<EOF

============================================================
  RuleIQ test WAF ready.
============================================================

  Web ACL ARN:      $ACL_ARN
  Log group:        $LOG_GROUP
  ExternalId:       $EXTERNAL_ID

  Quick-Create CFN (open in browser, accept role creation):
      $QUICK_CREATE

  After the stack reaches CREATE_COMPLETE, copy the RoleArn
  output from the Outputs tab and run:

      ROLE_ARN="<paste here>"
      curl -X POST $RULEIQ_URL/api/audits \\
        -H 'Content-Type: application/json' \\
        -d "{\"account_id\":\"$ACCOUNT_ID\",\"role_arn\":\"\$ROLE_ARN\",\"external_id\":\"$EXTERNAL_ID\",\"region\":\"$REGION\"}"

  Then poll:
      curl $RULEIQ_URL/api/audits | jq '.[0]'

============================================================
EOF
