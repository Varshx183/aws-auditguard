#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${CFN_ROLE_ARN:?Set CFN_ROLE_ARN}"
: "${RUNTIME_ROLE_ARN:?Set RUNTIME_ROLE_ARN}"
region="${AWS_REGION:-us-east-1}"
case "${OPERATION:-deploy}" in
  deploy)
    topic=$(aws cloudformation describe-stacks --region "$region" --stack-name aws-auditguard \
      --query "Stacks[0].Outputs[?OutputKey=='TopicArn'].OutputValue | [0]" --output text)
    [[ -n "$topic" && "$topic" != None ]] || { printf 'Deploy the base stack first.\n' >&2; exit 1; }
    aws cloudformation deploy --region "$region" --stack-name aws-auditguard-detection \
      --template-file infrastructure/risky-ssh.json --capabilities CAPABILITY_IAM \
      --role-arn "$CFN_ROLE_ARN" --parameter-overrides "AlertTopicArn=$topic" \
      "RuntimeRoleArn=$RUNTIME_ROLE_ARN" "EnableFailureSimulation=${ENABLE_FAILURE_DEMO:-false}" \
      --tags Project=AWS-AuditGuard Purpose=Learning
    ;;
  delete)
    aws cloudformation delete-stack --region "$region" --stack-name aws-auditguard-detection --role-arn "$CFN_ROLE_ARN"
    aws cloudformation wait stack-delete-complete --region "$region" --stack-name aws-auditguard-detection
    ;;
  *) printf 'OPERATION must be deploy or delete.\n' >&2; exit 1 ;;
esac
