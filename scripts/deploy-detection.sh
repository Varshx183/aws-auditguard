#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
region="${AWS_REGION:-us-east-1}"
base_stack="${STACK_NAME:-aws-auditguard}"
detection_stack="${DETECTION_STACK_NAME:-${base_stack}-detection}"
trail=$(aws cloudformation describe-stacks --region "$region" --stack-name "$base_stack" --query "Stacks[0].Outputs[?OutputKey=='TrailName'].OutputValue | [0]" --output text)
logging=$(aws cloudtrail get-trail-status --region "$region" --name "$trail" --query IsLogging --output text)
[[ "$logging" == True ]] || { printf 'Base trail must be logging before deployment.\n' >&2; exit 1; }
topic=$(aws cloudformation describe-stacks --region "$region" --stack-name "$base_stack" --query "Stacks[0].Outputs[?OutputKey=='TopicArn'].OutputValue | [0]" --output text)
[[ -n "$topic" && "$topic" != None ]] || { printf 'Base SNS topic missing.\n' >&2; exit 1; }
aws cloudformation deploy --region "$region" --stack-name "$detection_stack" \
  --template-file infrastructure/risky-ssh.json --capabilities CAPABILITY_IAM \
  --parameter-overrides "AlertTopicArn=$topic" --tags Project=AWS-AuditGuard Purpose=Learning
