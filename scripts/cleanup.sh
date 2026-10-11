#!/usr/bin/env bash
set -euo pipefail
region="${AWS_REGION:-us-east-1}"
stack="${STACK_NAME:-aws-auditguard}"
bucket=$(aws cloudformation describe-stacks --region "$region" --stack-name "$stack" \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue | [0]" --output text)
[[ -n "$bucket" && "$bucket" != None ]] || { printf 'Bucket output missing.\n' >&2; exit 1; }
printf 'Delete stack %s in %s. Audit bucket %s and its logs will be retained.\n' "$stack" "$region" "$bucket"
read -r -p 'Type the stack name to confirm: ' confirmation
[[ "$confirmation" == "$stack" ]] || exit 1
aws cloudformation delete-stack --region "$region" --stack-name "$stack"
aws cloudformation wait stack-delete-complete --region "$region" --stack-name "$stack"
printf 'Stack deleted. Retained bucket: %s\n' "$bucket"
printf 'To permanently delete the retained audit logs, review docs/cleanup.md.\n'
