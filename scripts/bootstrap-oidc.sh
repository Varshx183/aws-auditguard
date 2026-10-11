#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
region="${AWS_REGION:-us-east-1}"
oidc_subject="${GITHUB_OIDC_SUBJECT:-repo:Varshx183@207301812/aws-auditguard@1413488585:ref:refs/heads/main}"
account=$(aws sts get-caller-identity --query Account --output text)
provider="arn:aws:iam::$account:oidc-provider/token.actions.githubusercontent.com"
existing=$(aws iam list-open-id-connect-providers --query "OpenIDConnectProviderList[?Arn=='$provider'].Arn | [0]" --output text)
[[ "$existing" != None ]] || existing=''
if [[ -n "$existing" ]]; then
  audiences=$(aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$existing" --query 'ClientIDList' --output text)
  [[ " $audiences " == *sts.amazonaws.com* ]] || { printf 'Existing provider needs sts.amazonaws.com audience; review IAM provider settings.\n' >&2; exit 1; }
fi
aws cloudformation deploy --region "$region" --stack-name aws-auditguard-oidc \
  --template-file infrastructure/github-oidc.json --capabilities CAPABILITY_IAM \
  --parameter-overrides "ExistingProviderArn=$existing" "GitHubOidcSubject=$oidc_subject" \
  --tags Project=AWS-AuditGuard Purpose=Learning
aws cloudformation describe-stacks --region "$region" --stack-name aws-auditguard-oidc \
  --query 'Stacks[0].Outputs' --output table
