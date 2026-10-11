# Project summary

## What we built

AWS AuditGuard is a single-Region security monitoring lab. CloudTrail records management API activity in S3 and CloudWatch Logs. A JSON metric filter selects successful EC2 CreateSecurityGroup calls, a CloudWatch alarm detects a count of at least one, and SNS sends an email.

## How we built and verified it

1. Defined ten resources in a CloudFormation YAML template: S3 bucket and policy, log group, delivery role, trail, SNS topic and policy, metric filter, and alarm.
2. Added Bash scripts for deployment, temporary security group testing, and stack cleanup.
3. Added GitHub Actions validation using cfn-lint, shell syntax checks, and JSON parsing; the same local checks passed before publication.
4. Deployed from AWS CloudShell with AWS CLI to us-east-1.
5. Created and deleted an unattached security group, inspected its CloudWatch event, checked trail delivery status, and verified the alarm transition.
6. Confirmed alarm email receipt with the project owner. Matched the test event in a downloaded S3 log. During cleanup, the owner reported the stack was absent and the retained bucket lookup returned an empty list.

## Improvements implemented

- Repeatable CloudFormation deployment and documented parameters.
- An automated notification for a specific API action.
- Successful-event filtering to exclude failed creation attempts.
- S3 encryption, public access blocking, TLS enforcement, and trail-scoped bucket permissions.
- Delivery-role permissions scoped to the project log group.
- Seven-day default log retention and an instance-free test.
- Automatic removal of the test security group and explicit retention of audit evidence during stack deletion.
- Repository validation workflow and separation of synthetic examples from live evidence.

These are implemented design features; no before-and-after operational or cost baseline was measured.

## Tools and demonstrated skills

| Tools | Skills |
|---|---|
| CloudTrail and S3 | Audit logging, API event interpretation, storage policies |
| CloudWatch Logs, metric filters, alarms | Detection configuration, log filtering, alarm investigation |
| SNS | Email subscription and notification validation |
| CloudFormation and IAM | Infrastructure as code, resource dependencies, service permissions |
| AWS CLI, CloudShell, Bash | Deployment automation, troubleshooting, resource cleanup |
| GitHub, GitHub Actions, cfn-lint | Version control, validation workflows, technical documentation |

## Future improvements

Use a scoped non-root session and root MFA; evaluate broader regional/global coverage, additional detections, and digest validation. Do not claim these as completed.

## Detection engineering extension — October 11, 2026

Added an optional EventBridge/Lambda detector for world-open SSH, positive and negative Python tests, a synthetic offline demo, and an investigation runbook. Detection checks protocol, port ranges, IPv4/IPv6, and correlated permissions. The owner subsequently confirmed successful live deployment, test-group cleanup, and receipt of the exact SSH alert email. It adds Python unit testing, detection design, false-positive analysis, and incident triage documentation to the demonstrated skills.

## Secure deployment and resilience iteration

Added a manual GitHub OIDC workflow with main-branch/audience-bound trust and separate deployment/runtime roles; EventBridge delivery and Lambda processing failure queues; six health alarms; a guarded synthetic failure inspection/replay exercise; and current-state modification detection with ingress/egress discrimination. Code and infrastructure checks cover these additions. Their live AWS tests remain pending. Screenshot capture guidance documents where to collect genuine evidence before teardown.
