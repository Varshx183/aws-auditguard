#!/usr/bin/env bash
set -euo pipefail
region="${AWS_REGION:-us-east-1}"
stack="${DETECTION_STACK_NAME:-aws-auditguard-detection}"
read -r -p "Type $stack to delete the detection add-on and its function logs: " confirmation
[[ "$confirmation" == "$stack" ]] || exit 1
aws cloudformation delete-stack --region "$region" --stack-name "$stack"
aws cloudformation wait stack-delete-complete --region "$region" --stack-name "$stack"
printf 'Detection add-on deleted. Run base cleanup separately if no longer needed.\n'
