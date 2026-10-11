# Investigation runbook: world-open SSH

**Trigger:** SNS email `AuditGuard: world-open SSH rule detected`, rule `AG-SSH-001` (authorization) or `AG-SSH-002` (modification). For AG-SSH-002, the finding describes current rule state at lookup time, not proof of the exact historical state.

## 1. Validate the signal

Record event ID, UTC time, Region, security group, actor ARN, and the matched permission in a private incident note. Correlate the event ID in CloudTrail with the email. Check the API succeeded and that port 22 and the world CIDR belong to the same permission. Repeated notifications with the same event ID may be retries.

## 2. Establish current exposure

Use a read-only investigation role in the event's Region. Set the group ID from the alert:

```bash
export AWS_REGION=us-east-1
export GROUP_ID=sg-REPLACE_WITH_ALERT_GROUP
aws ec2 describe-security-groups --region "$AWS_REGION" --group-ids "$GROUP_ID"
aws ec2 describe-network-interfaces --region "$AWS_REGION" \
  --filters "Name=group-id,Values=$GROUP_ID" \
  --query 'NetworkInterfaces[].{Interface:NetworkInterfaceId,Instance:Attachment.InstanceId,PublicIP:Association.PublicIp,Status:Status}'
```

An absent group may indicate the disposable test was already cleaned up. A world-open rule on an unattached group is a configuration finding, not evidence of an exposed server. For attached workloads, assess routing, public addresses, network ACLs, host firewall, SSH service, and business purpose; group rules alone do not establish reachability.

## 3. Identify intent and ownership

Review CloudTrail session issuer/actor, related activity, change tickets, resource tags, and service owner. Determine whether the change was an authorized exercise, an approved exception, an error, or suspicious activity. Do not assume compromise solely from this finding.

## 4. Contain with authorization

For unintended exposure, coordinate with the owner to remove the specific offending rule or narrow its source. Prefer a reviewed security-group rule ID to avoid affecting unrelated permissions. Do not delete a shared group or revoke every ingress rule. Confirm alternate access before changing remote-administration access.

For a suspected compromised identity, follow the organization's identity incident process and preserve relevant logs. This project performs no automatic remediation.

## 5. Verify and close

Confirm the risky permission is removed or an exception is recorded, check intended access still works, and save a sanitized timeline. Note action time, detection time, response time, ownership, decision, and follow-up. Distinguish rule removal from proof that no exploitation occurred.

## Detector troubleshooting

If no alert arrives, check the active trail, Region, confirmed SNS subscription, EventBridge matched events/failed invocations, Lambda Errors/Throttles and function logs, and execution-role publish permission. The function logs only counts; use the source CloudTrail event for detailed investigation. An empty function log does not prove there were no risky events.

For failed processing, inspect the processing-failures queue and Lambda health alarms; transport failures appear in the separate delivery-failures queue. The synthetic lab replay helper is not a generic incident replay tool. See `docs/reliability.md`.
