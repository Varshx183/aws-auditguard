#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
region="${AWS_REGION:-us-east-1}"
stack="${STACK_NAME:-aws-auditguard}"
read -r -p 'SNS alert email: ' email
aws sts get-caller-identity --region "$region"
aws cloudformation deploy --region "$region" --stack-name "$stack" \
  --template-file infrastructure/auditguard.yaml --capabilities CAPABILITY_IAM \
  --parameter-overrides "AlertEmail=$email" \
  --tags Project=AWS-AuditGuard Purpose=Learning
aws cloudformation describe-stacks --region "$region" --stack-name "$stack" \
  --query 'Stacks[0].Outputs' --output table
printf 'Confirm the SNS subscription in your email before testing.\n'
