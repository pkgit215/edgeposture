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
else
  echo "IPSet $IPSET_NAME already exists (Id=$IPSET_ID); reusing."
fi
IPSET_ARN=$(aws wafv2 list-ip-sets --scope "$SCOPE" --region "$REGION" \
  --query "IPSets[?Name=='$IPSET_NAME'].ARN | [0]" --output text)
echo "IPSet ARN: $IPSET_ARN"

# 2) LogGroup ------------------------------------------------------------------
if ! aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP" --region "$REGION" \
    --query "logGroups[?logGroupName=='$LOG_GROUP']" --output text | grep -q "$LOG_GROUP"; then
  echo "Creating log group $LOG_GROUP..."
  aws logs create-log-group --log-group-name "$LOG_GROUP" --region "$REGION"
  aws logs put-retention-policy --log-group-name "$LOG_GROUP" --retention-in-days 7 --region "$REGION"
else
  echo "Log group $LOG_GROUP already exists; reusing."
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
    --cli-binary-format raw-in-base64-out \
    --name "$ACL_NAME" \
    --scope "$SCOPE" \
    --region "$REGION" \
    --default-action '{"Allow": {}}' \
    --visibility-config "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=ruleiq-test-acl" \
    --rules "$RULES_JSON")
  ACL_ID=$(echo "$CREATE_OUT" | jq -r '.Summary.Id')
else
  echo "Web ACL $ACL_NAME already exists (Id=$ACL_ID); reusing."
fi

ACL_ARN=$(aws wafv2 list-web-acls --scope "$SCOPE" --region "$REGION" \
  --query "WebACLs[?Name=='$ACL_NAME'].ARN | [0]" --output text)
echo "Web ACL ARN: $ACL_ARN"

# 4) Logging configuration -----------------------------------------------------
echo "Configuring WAF logging → $LOG_GROUP..."
aws wafv2 put-logging-configuration \
  --logging-configuration "{\"ResourceArn\": \"$ACL_ARN\", \"LogDestinationConfigs\": [\"${LOG_GROUP_ARN%:*}\"]}" \
  --region "$REGION" >/dev/null || true

# 5) Seed log stream + ~5000 fake events --------------------------------------
# CloudWatch PutLogEvents constraints we honor here:
#   • ≤ 500 events per batch              (we use 500; API allows 10,000)
#   • ≤ 1 MB per batch                    (500 events ≈ 175 KB)
#   • ≤ 256 KB per event                  (each event ≈ 350 B)
#   • Batch span ≤ 24h                    (we bucket by UTC calendar day)
#   • No event older than now − 14 days   (we use a 7-day window)
#   • No event newer than now + 2h        (all events are in the past)
#   • Events ascending by timestamp       (each batch sorted ascending)
#   • Fresh per-run stream                (no sequenceToken plumbing needed)
SEED_STREAM="ruleiq-seed-$(date +%s)"
aws logs create-log-stream \
  --log-group-name "$LOG_GROUP" \
  --log-stream-name "$SEED_STREAM" \
  --region "$REGION"

SEED_DIR=$(mktemp -d)
trap 'rm -rf "$SEED_DIR"' EXIT

echo "Generating ~5000 events across 4 rules (LegacyDeadRule intentionally zero)..."
echo "Window: last 7 days, bucketed per UTC calendar day to satisfy 24h-per-batch limit."

python3 - "$SEED_DIR" "$LOG_GROUP" "$SEED_STREAM" "$ACL_ARN" <<'PY'
import json, os, random, sys, time

seed_dir, log_group, stream, acl_arn = sys.argv[1:5]
now_ms = int(time.time() * 1000)

WINDOW_DAYS = 7                  # well inside the 14-day past-cutoff
WINDOW_MS = WINDOW_DAYS * 86400_000
DAY_MS = 86400_000
PER_BATCH = 500                  # well under the 10,000-event API limit

events = []
def push(rule, action, n):
    for _ in range(n):
        ts = now_ms - random.randint(0, WINDOW_MS - 1)
        msg = {
            "timestamp": ts,
            "formatVersion": 1,
            "webaclId": acl_arn,
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
# LegacyDeadRule: zero events on purpose

# Bucket by UTC calendar day so every batch spans <= 24 h.
buckets = {}
for ev in events:
    buckets.setdefault(ev["timestamp"] // DAY_MS, []).append(ev)
sorted_days = sorted(buckets.keys())
day_total = len(sorted_days)

manifest_path = os.path.join(seed_dir, "manifest.tsv")
with open(manifest_path, "w") as mf:
    for day_i, day in enumerate(sorted_days, 1):
        # Sort each bucket ascending — PutLogEvents requires monotonic order.
        day_events = sorted(buckets[day], key=lambda e: e["timestamp"])
        sub_batches = [
            day_events[i:i + PER_BATCH]
            for i in range(0, len(day_events), PER_BATCH)
        ]
        batch_total = len(sub_batches)
        for batch_i, batch in enumerate(sub_batches, 1):
            path = os.path.join(seed_dir, f"day-{day_i:02d}-batch-{batch_i:02d}.json")
            with open(path, "w") as fh:
                json.dump(
                    {
                        "logGroupName": log_group,
                        "logStreamName": stream,
                        "logEvents": batch,
                    },
                    fh,
                )
            mf.write(f"{day_i}\t{day_total}\t{batch_i}\t{batch_total}\t{len(batch)}\t{path}\n")
PY

TOTAL=0
while IFS=$'\t' read -r DAY_I DAY_TOTAL BATCH_I BATCH_TOTAL COUNT FILE; do
  aws logs put-log-events \
    --region "$REGION" \
    --cli-input-json "file://$FILE" >/dev/null
  TOTAL=$((TOTAL + COUNT))
  echo "Seeded day $DAY_I/$DAY_TOTAL, batch $BATCH_I/$BATCH_TOTAL (events so far: $TOTAL / 5000)"
done < "$SEED_DIR/manifest.tsv"

echo
echo "Done. Stream: $SEED_STREAM."
echo "If you ran this script before and got a partial seed, those events still"
echo "live in the previous stream(s) under the same log group — the audit reads"
echo "them all regardless. Each re-run appends another ~5000 events; for a"
echo "clean re-seed: bash scripts/teardown-test-waf.sh && bash scripts/setup-test-waf.sh"

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
