#!/usr/bin/env bash
set -euo pipefail
region="${AWS_REGION:-us-east-1}"
: "${VPC_ID:?Set VPC_ID to an existing VPC in the lab Region}"
group_id=''
cleanup() {
  if [[ -n "$group_id" ]]; then
    aws ec2 delete-security-group --region "$region" --group-id "$group_id" || {
      printf 'Delete test security group manually: %s\n' "$group_id" >&2
      return 1
    }
  fi
}
trap cleanup EXIT
aws ec2 describe-vpcs --region "$region" --vpc-ids "$VPC_ID" --query 'Vpcs[0].VpcId' --output text
group_id=$(aws ec2 create-security-group --region "$region" --vpc-id "$VPC_ID" \
  --group-name "auditguard-test-$(date +%s)-$RANDOM" \
  --description 'Temporary AuditGuard alert test; no inbound rules or attached instances' \
  --query GroupId --output text)
printf 'Created %s. It will be deleted now; its creation event remains in CloudTrail.\n' "$group_id"
printf 'Allow several minutes for delivery and alarm evaluation. Check CloudWatch and email.\n'
