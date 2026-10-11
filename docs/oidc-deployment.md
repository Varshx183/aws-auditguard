# GitHub OIDC deployment and live validation

**Status:** Workflow, scoped roles, reliability resources, and rule-modification support are implemented and locally tested. Their new live validation is pending. The earlier ingress-authorization detector was live-tested on October 11, 2026.

This workflow deploys **only the detection stack**. An operator provisions the base audit trail and the one-time IAM bootstrap in CloudShell. GitHub receives temporary credentials through OIDC; no AWS access keys are stored in GitHub.

## Permission boundaries

| Principal | Purpose | Limits |
|---|---|---|
| GitHub OIDC role | Create/execute changesets and delete the detection stack | Exact repository `main` subject, STS audience, fixed detection stack and CloudFormation role |
| CloudFormation role | Provision detection resources | Fixed detector/rule/log names and detection queue/alarm prefixes; pass only the pre-provisioned runtime role |
| Lambda runtime role | Read rule direction/state and notify | EC2 DescribeSecurityGroupRules in the deployment Region, specific SNS topic prefix, processing queue, and function log group |

Neither deployment role can create or edit IAM roles. Resource-prefix restrictions are not a security boundary against malicious trusted maintainers: a maintainer able to deploy arbitrary Lambda code can exercise the runtime role's allowed reads/publishes. Protect `main` and review deployment code. The workflow is manual, main-only, uses commit-pinned actions, and serializes deployments. `logs:DescribeLogGroups` and `ec2:DescribeSecurityGroupRules` require resource `*`; both are Region-limited.

The bootstrap reuses an existing GitHub OIDC provider, or creates one with Retain policy. Do not delete a shared provider used by other projects.

## 1. Prepare AWS (CloudShell)

Use the **N. Virginia / us-east-1** console for every AWS screenshot. The CloudShell host can be in another Region, but these commands explicitly target us-east-1. This walkthrough assumes the previous detection stack was deleted; an older stack-owned runtime role must be cleaned up before switching to the OIDC-owned role, because the scoped deployment role deliberately cannot delete IAM roles.

```bash
cd ~/aws-auditguard
git pull --ff-only
export AWS_REGION=us-east-1
export STACK_NAME=aws-auditguard
bash scripts/deploy.sh
# Confirm the new SNS subscription email.
bash scripts/bootstrap-oidc.sh
```

The bootstrap needs operator permissions for IAM OIDC providers, roles and inline policies, plus CloudFormation. This is the one-time privileged setup; use a scoped administrator session rather than publishing credentials. Capture screenshots S1 and S2 in `docs/screenshots.md`.

## 2. Configure GitHub repository variables

Open repository **Settings → Secrets and variables → Actions → Variables → New repository variable**. Copy the bootstrap outputs into these variables:

| GitHub variable | CloudFormation output |
|---|---|
| `AWS_ROLE_ARN` | `GitHubDeployRoleArn` |
| `CFN_ROLE_ARN` | `CloudFormationRoleArn` |
| `RUNTIME_ROLE_ARN` | `RuntimeRoleArn` |

These are role identifiers, not access keys. Do not create AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY secrets.

Open **Actions → Deploy detection with OIDC → Run workflow**. Select branch `main`, operation `deploy`, and enable the failure demo for this exercise. The workflow validates code, requests short-lived credentials, and deploys `aws-auditguard-detection`. Confirm success before testing. Capture S3.

If the base stack was previously deployed from an older commit, update it with the current `deploy.sh` so its SNS topic policy permits the new health alarms.

## 3. Verify a rule modification

In CloudShell, choose an existing lab VPC, then run:

```bash
aws ec2 describe-vpcs --region us-east-1 --query 'Vpcs[].{VpcId:VpcId,Default:IsDefault}' --output table
export VPC_ID=vpc-REPLACE_WITH_LAB_VPC
bash scripts/test-modified-ssh.sh
```

The script creates an unattached group, adds private SSH, and changes that rule to world-open SSH. It pauses before deletion so Lambda can read the rule and you can take screenshots S4 and S5. Wait for the SSH email with **ruleId AG-SSH-002**, `eventName: ModifySecurityGroupRules`, and `evidenceBasis: current-rule-state`. Then press Enter in CloudShell to delete the test group. Keep the deletion output for evidence.

This detector evaluates current state after the change, not a historical snapshot. If the rule is removed before lookup, no finding can be established; logs report unresolved rule IDs. An alert for a description-only change can occur if the rule remains risky.

## 4. Verify processing failure recovery

```bash
python3 scripts/failure-lab.py invoke
```

Keep the printed synthetic event ID. This directly invokes Lambda asynchronously with an explicitly marked synthetic event; it **does not** simulate an AWS SNS outage or validate EventBridge transport failure. The enabled lab guard raises before SNS publish. After two retries, Lambda should preserve an invocation record in the processing-failures queue. Allow several minutes.

```bash
python3 scripts/failure-lab.py inspect
```

Capture S6 and S7 before replay. `inspect` prints only a sanitized synthetic-record summary and releases the message without deleting it. Replay exactly the event ID printed by `invoke`:

```bash
python3 scripts/failure-lab.py replay --event-id auditguard-failure-test-REPLACE_WITH_ID
```

The replay removes the injection marker and invokes Lambda synchronously. Only a successful finding response leads to deletion of that exact synthetic message. SNS publish acceptance is not proof of final email receipt; check your inbox. Repeated delivery can still cause duplicate alerts. Inspect/receive operations can change approximate queue metrics temporarily.

Run the GitHub deployment workflow again with the failure-demo option **off** after testing. Its default is off. Capture the configuration if retaining the deployment.

## 5. Cleanup, in order

Capture all screenshots first; stack deletion removes function logs, queues, and alarms.

1. Run **Deploy detection with OIDC** with operation `delete`. Save the successful run (S8).
2. In CloudShell, run `bash scripts/cleanup.sh` to remove the base stack; record the retained bucket name.
3. Empty and delete that exact retained S3 bucket using `docs/cleanup.md`.
4. When you no longer want GitHub deployment access, remove the bootstrap roles:

```bash
aws cloudformation delete-stack --stack-name aws-auditguard-oidc --region us-east-1
aws cloudformation wait stack-delete-complete --stack-name aws-auditguard-oidc --region us-east-1
```

5. Remove the three GitHub variables if no longer needed. A created OIDC provider is intentionally retained; leave shared providers in place. Remove it manually in IAM only after checking it is not used elsewhere.

CloudShell cleanup of an OIDC-managed detection stack also needs permission to pass the retained CloudFormation service role; the GitHub delete operation is the documented path. Review Billing after usage reporting catches up. This extension adds SQS requests/storage and six standard health alarms; zero cost is not guaranteed.

## Troubleshooting

- OIDC denied: check the immutable subject below, main branch, STS audience, role variable, and provider client IDs. This workflow deliberately does not use a GitHub Environment because environment subjects have a different format.
- CloudFormation access denied: inspect failed stack events and the denied action; refine only the required scoped permission instead of granting AdministratorAccess.
- IAM deletion failure on an old detection stack: use your operator session to finish deleting the old stack before creating the OIDC-managed replacement.
- No modification alert: keep the group until lookup, check function Errors/logs and ProcessingFailures queue; unsupported request shapes are retained for investigation after retries.
- Health email missing: confirm base SNS subscription and current topic policy. All notifications share the base topic; an SNS-wide failure can also prevent health email, so inspect metrics/queues directly.

## References

- [GitHub OIDC with AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)
- [EventBridge delivery DLQs](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html)
- [Lambda asynchronous failure destinations](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-retain-records.html)
- [EC2 ModifySecurityGroupRules](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySecurityGroupRules.html)

- [CloudFormation action/resource authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudformation.html)

## OIDC subject-format correction

GitHub repositories created after July 15, 2026 use immutable owner and repository IDs in their default subject. This repository was created October 10, 2026. Its bootstrap therefore requires this exact subject:

```text
repo:Varshx183@207301812/aws-auditguard@1413488585:ref:refs/heads/main
```

An earlier version used the legacy name-only subject, causing the reported `sts:AssumeRoleWithWebIdentity` denial. To update the deployed trust policy without recreating roles or widening access:

```bash
cd ~/aws-auditguard
git pull --ff-only
export AWS_REGION=us-east-1
bash scripts/bootstrap-oidc.sh
```

After successful update, retake S2 (the two GitHub IDs should now be visible). Start a **new** deployment run from main so it uses the updated action pins; rerunning the old job retains its old workflow. Keep the same role variables. If federation still fails, inspect the actual role trust and any customized GitHub OIDC subject before changing permissions. The updated policy intentionally does not accept both legacy and immutable formats or use wildcards.

The actions now use Node 24 and the runner is fixed at Ubuntu 24.04. These remove separate runtime warnings; action upgrades alone do not repair an AWS trust mismatch.

Reference: [GitHub immutable subject format](https://docs.github.com/en/actions/reference/security/oidc#immutable-subject-claims).
