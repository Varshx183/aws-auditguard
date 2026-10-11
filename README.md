# AWS AuditGuard

I built AuditGuard to practice detecting risky AWS changes and investigating what happened. It started with a security-group creation alarm, then I added public SSH detection, GitHub OIDC deployment, and failure recovery.

## What it does

- Records management API activity with CloudTrail, S3, and CloudWatch Logs.
- Sends SNS email alerts for security-group creation and public SSH access, including IPv4, IPv6, and port ranges that include port 22.
- Detects changes to existing rules by checking their current state with a read-only EC2 lookup.
- Keeps failed Lambda events in SQS after retries, with a script to replay the synthetic test event.
- Deploys the detection stack through GitHub Actions using OIDC and scoped IAM roles, without storing AWS access keys in GitHub.

CloudFormation provisions the resources. CloudTrail feeds the audit logs, while EventBridge routes relevant API events to the Python detector. CloudWatch alarms monitor failures.

## What I tested

I tested the project in `us-east-1` using temporary, unattached security groups and received the alert emails. For recovery testing, I deliberately failed a synthetic event, confirmed three execution attempts, replayed it from SQS, and received the resulting email. The script then deleted the queued message.

I also verified the error alarm entering ALARM and returning to OK. The repository has **52 automated tests** covering detection logic, permission boundaries, and replay behavior.

After testing, I deleted the lab stacks, retained audit bucket, and test groups. The project is available to redeploy; it is not continuously running.

## Try it locally

No AWS account is needed for the synthetic demo or unit tests:

```bash
git clone https://github.com/Varshx183/aws-auditguard.git
cd aws-auditguard
python3 scripts/demo.py
python3 -m unittest discover -s tests -v
```

For a live deployment, follow the [setup guide](docs/oidc-deployment.md). AWS resources can incur charges; follow the [cleanup guide](docs/cleanup.md) when finished.

## What I learned

The most useful parts were narrowing IAM permissions, troubleshooting OIDC trust, avoiding false positives across separate security-group rules, and checking that failed events could be recovered.

This is a single-region lab. Rule-modification detection checks current state, so a rule deleted before the lookup may not produce a finding. The failure exercise tests an application error, not an AWS service outage.

**Tools:** CloudFormation, CloudTrail, EventBridge, Lambda, SQS, SNS, CloudWatch, S3, IAM, Python, Bash, AWS CLI, GitHub Actions, and cfn-lint.

More detail: [Detection design](docs/detection-design.md) · [Failure recovery](docs/reliability.md) · [Investigation runbook](docs/investigation-runbook.md)
