#!/usr/bin/env bash
# RuleIQ AWS bootstrap — creates IAM/ECR/OIDC, no static creds anywhere.
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-1}"
GH_OWNER="pkgit215"
GH_REPO="ruleiq"
ECR_REPO="ruleiq"
INSTANCE_ROLE="ruleiq-apprunner-instance"
ACCESS_ROLE="ruleiq-apprunner-ecr-access"
DEPLOYER_ROLE="ruleiq-github-deployer"
OIDC_HOST="token.actions.githubusercontent.com"
OPENAI_SECRET="ruleiq/openai"
MONGO_SECRET="ruleiq/mongodb"

for cmd in aws gh jq; do command -v $cmd >/dev/null || { echo "Missing: $cmd"; exit 1; }; done
aws sts get-caller-identity >/dev/null
gh auth status >/dev/null 2>&1 || { echo "Run: gh auth login"; exit 1; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Account: $ACCOUNT_ID  Region: $AWS_REGION"

# 1. GitHub repo
gh repo view "$GH_OWNER/$GH_REPO" >/dev/null 2>&1 \
  || gh repo create "$GH_OWNER/$GH_REPO" --private --description "RuleIQ — AI-powered AWS WAF audit POC"

# 2. ECR
aws ecr describe-repositories --repository-names "$ECR_REPO" --region "$AWS_REGION" >/dev/null 2>&1 \
  || aws ecr create-repository --repository-name "$ECR_REPO" --region "$AWS_REGION" \
       --image-scanning-configuration scanOnPush=true >/dev/null

# 3. GitHub OIDC provider
OIDC_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_HOST}"
aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$OIDC_ARN" >/dev/null 2>&1 \
  || aws iam create-open-id-connect-provider \
       --url "https://${OIDC_HOST}" \
       --client-id-list "sts.amazonaws.com" \
       --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1" >/dev/null

# 4. Deployer role (GitHub Actions assumes via OIDC)
DEPLOYER_TRUST=$(cat <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"Federated":"${OIDC_ARN}"},
 "Action":"sts:AssumeRoleWithWebIdentity",
 "Condition":{
   "StringEquals":{"${OIDC_HOST}:aud":"sts.amazonaws.com"},
   "StringLike":{"${OIDC_HOST}:sub":"repo:${GH_OWNER}/${GH_REPO}:*"}}}]}
JSON
)
aws iam get-role --role-name "$DEPLOYER_ROLE" >/dev/null 2>&1 \
  || aws iam create-role --role-name "$DEPLOYER_ROLE" \
       --assume-role-policy-document "$DEPLOYER_TRUST" >/dev/null

DEPLOYER_POLICY=$(cat <<JSON
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["ecr:GetAuthorizationToken"],"Resource":"*"},
 {"Effect":"Allow","Action":["ecr:BatchCheckLayerAvailability","ecr:CompleteLayerUpload","ecr:InitiateLayerUpload","ecr:PutImage","ecr:UploadLayerPart","ecr:DescribeRepositories","ecr:DescribeImages","ecr:BatchGetImage"],
  "Resource":"arn:aws:ecr:${AWS_REGION}:${ACCOUNT_ID}:repository/${ECR_REPO}"},
 {"Effect":"Allow","Action":["apprunner:CreateService","apprunner:UpdateService","apprunner:DescribeService","apprunner:ListServices","apprunner:StartDeployment","apprunner:TagResource","apprunner:DescribeOperation"],"Resource":"*"},
 {"Effect":"Allow","Action":["iam:PassRole"],
  "Resource":["arn:aws:iam::${ACCOUNT_ID}:role/${INSTANCE_ROLE}","arn:aws:iam::${ACCOUNT_ID}:role/${ACCESS_ROLE}"]}]}
JSON
)
aws iam put-role-policy --role-name "$DEPLOYER_ROLE" \
  --policy-name "ruleiq-deployer-inline" --policy-document "$DEPLOYER_POLICY"

# 5. App Runner instance role (the runtime identity)
INSTANCE_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"tasks.apprunner.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam get-role --role-name "$INSTANCE_ROLE" >/dev/null 2>&1 \
  || aws iam create-role --role-name "$INSTANCE_ROLE" --assume-role-policy-document "$INSTANCE_TRUST" >/dev/null

INSTANCE_POLICY=$(cat <<JSON
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["secretsmanager:GetSecretValue"],
  "Resource":["arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${OPENAI_SECRET}-*",
              "arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${MONGO_SECRET}-*"]},
 {"Effect":"Allow","Action":["sts:AssumeRole"],"Resource":"arn:aws:iam::*:role/*"}]}
JSON
)
aws iam put-role-policy --role-name "$INSTANCE_ROLE" \
  --policy-name "ruleiq-instance-inline" --policy-document "$INSTANCE_POLICY"

# 6. App Runner ECR access role
ACCESS_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"build.apprunner.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam get-role --role-name "$ACCESS_ROLE" >/dev/null 2>&1 \
  || aws iam create-role --role-name "$ACCESS_ROLE" --assume-role-policy-document "$ACCESS_TRUST" >/dev/null
aws iam attach-role-policy --role-name "$ACCESS_ROLE" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess" 2>/dev/null || true

# 7. Output ARNs
mkdir -p .ruleiq
cat > .ruleiq/arns.json <<JSON
{
  "account_id": "${ACCOUNT_ID}",
  "region": "${AWS_REGION}",
  "github": "${GH_OWNER}/${GH_REPO}",
  "ecr_repo": "${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}",
  "deployer_role_arn": "arn:aws:iam::${ACCOUNT_ID}:role/${DEPLOYER_ROLE}",
  "instance_role_arn": "arn:aws:iam::${ACCOUNT_ID}:role/${INSTANCE_ROLE}",
  "access_role_arn":   "arn:aws:iam::${ACCOUNT_ID}:role/${ACCESS_ROLE}",
  "openai_secret_arn": "arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${OPENAI_SECRET}",
  "mongo_secret_arn":  "arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${MONGO_SECRET}"
}
JSON
cat .ruleiq/arns.json
echo
echo "Next — populate secrets (run in your terminal, not here):"
echo "  aws secretsmanager create-secret --name ${OPENAI_SECRET} --region ${AWS_REGION} --secret-string \"\$(op read 'op://Personal/OpenAI/credential')\""
echo "  aws secretsmanager create-secret --name ${MONGO_SECRET}  --region ${AWS_REGION} --secret-string '{\"uri\":\"<atlas-srv-uri>\"}'"


