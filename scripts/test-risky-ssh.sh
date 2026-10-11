#!/usr/bin/env bash
set -euo pipefail
region="${AWS_REGION:-us-east-1}"
: "${VPC_ID:?Set VPC_ID to an existing lab VPC in the selected Region}"
group_id=''
cleanup() {
  if [[ -n "$group_id" ]]; then
    aws ec2 delete-security-group --region "$region" --group-id "$group_id" || {
      printf 'Cleanup failed. Remove the unattached lab group manually: %s\n' "$group_id" >&2
      return 1
    }
  fi
}
trap cleanup EXIT
aws ec2 describe-vpcs --region "$region" --vpc-ids "$VPC_ID" --query 'Vpcs[0].VpcId' --output text
group_id=$(aws ec2 create-security-group --region "$region" --vpc-id "$VPC_ID" \
  --group-name "auditguard-ssh-test-$(date +%s)-$RANDOM" \
  --description 'Unattached disposable AuditGuard detection test' --query GroupId --output text)
# Only the newly created group is changed; no instances or interfaces are attached.
aws ec2 authorize-security-group-ingress --region "$region" --group-id "$group_id" \
  --ip-permissions '[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Temporary detection test"}]}]'
printf 'Test API call completed at %s. Group %s will be deleted now.\n' "$(date -u +%FT%TZ)" "$group_id"
printf 'Check for the email subject: AuditGuard: world-open SSH rule detected\n'
