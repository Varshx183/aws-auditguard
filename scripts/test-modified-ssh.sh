#!/usr/bin/env bash
set -euo pipefail
region="${AWS_REGION:-us-east-1}"
: "${VPC_ID:?Set VPC_ID to an existing lab VPC}"
group_id=''
cleanup() {
  if [[ -n "$group_id" ]]; then
    aws ec2 delete-security-group --region "$region" --group-id "$group_id" || {
      printf 'Remove the unattached test group manually: %s\n' "$group_id" >&2; return 1;
    }
  fi
}
trap cleanup EXIT
aws ec2 describe-vpcs --region "$region" --vpc-ids "$VPC_ID" --query 'Vpcs[0].VpcId' --output text
group_id=$(aws ec2 create-security-group --region "$region" --vpc-id "$VPC_ID" \
  --group-name "auditguard-modify-test-$(date +%s)-$RANDOM" \
  --description 'Unattached disposable AuditGuard modification test' --query GroupId --output text)
rule_id=$(aws ec2 authorize-security-group-ingress --region "$region" --group-id "$group_id" \
  --ip-permissions '[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"10.0.0.0/8"}]}]' \
  --query 'SecurityGroupRules[0].SecurityGroupRuleId' --output text)
aws ec2 modify-security-group-rules --region "$region" --group-id "$group_id" \
  --security-group-rules "SecurityGroupRuleId=$rule_id,SecurityGroupRule={IpProtocol=tcp,FromPort=22,ToPort=22,CidrIpv4=0.0.0.0/0}"
printf 'Modified rule %s on unattached group %s.\n' "$rule_id" "$group_id"
printf 'Wait for the email with ruleId AG-SSH-002. Capture the rule and email screenshots now.\n'
printf 'Keep this group until the detector performs its read-only lookup.\n'
read -r -p 'After capturing evidence (or to abandon the test), press Enter to delete the group: ' unused
