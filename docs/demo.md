# Two-minute portfolio demo

## Offline demonstration (available now)

No credentials, AWS resources, or email delivery are needed:

```bash
python3 scripts/demo.py
python3 -m unittest discover -s tests -v
```

Expected demo: `risky-ssh: 1 finding(s)` and `safe-mixed-rules: 0 finding(s)`. Both events are synthetic. The second contains private SSH and public HTTPS in different permissions: it demonstrates a meaningful false-positive regression case.

Walk a reviewer through:

1. The architecture and the original live evidence in `docs/evidence.md`.
2. The matching logic in `detection/risky_ssh.py` and why each permission is evaluated independently.
3. The offline demo and positive/negative tests.
4. The analyst investigation steps and explicitly documented coverage gaps.

## Repeatable AWS validation

The ingress-authorization live test succeeded on October 11. The new OIDC, modification and failure-recovery walkthrough is in `docs/oidc-deployment.md`, with capture locations in `docs/screenshots.md`.

The original lab was cleaned up. Redeploy the base stack first; confirm the new SNS subscription. Review current costs: the add-on introduces Lambda invocations/logging and SNS notifications in addition to the base lab. It reuses the base trail instead of creating a second one.

```bash
export AWS_REGION=us-east-1
export STACK_NAME=aws-auditguard
bash scripts/deploy.sh
# Confirm the SNS subscription, then:
bash scripts/deploy-detection.sh
# Choose a lab VPC in this Region:
export VPC_ID=vpc-REPLACE_WITH_LAB_VPC
bash scripts/test-risky-ssh.sh
```

The test creates a new unattached group, authorizes world-open SSH on that group, and immediately deletes the group via an EXIT trap. It never attaches the group to a workload. Forced termination or an API failure can leave a resource; inspect the printed group ID if cleanup fails. Do not substitute an existing group into the script.

The baseline CreateSecurityGroup alarm may also email you. For the new detector, the expected subject is **AuditGuard: world-open SSH rule detected**. Verify the matching event ID/group and the Lambda invocation, not just any alarm email. Record fresh event and receipt times; do not reuse the original 147-second result.

## Teardown

Delete the add-on before the base stack:

```bash
bash scripts/cleanup-detection.sh
bash scripts/cleanup.sh
```

Then explicitly remove the retained base S3 bucket following `docs/cleanup.md`. Save only sanitized evidence intended for publication.

## Suggested evidence to capture after live validation

- Screenshot of passing automated checks.
- Sanitized detector email and matching CloudTrail event.
- Function invocation/log count and cleanup confirmation.

No fabricated screenshots or new live-success claims are included in this repository.
