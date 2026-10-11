# Screenshot capture checklist

Capture genuine results during the walkthrough in `docs/oidc-deployment.md`. The AWS console must show **us-east-1 (N. Virginia)**. Keep raw images private; upload only redacted copies you have inspected. Never capture temporary credentials, tokens, or secret values. Hide your account ID, email address, personal identity details and unnecessary ARNs. Keep status, timestamps, rule logic, and test labels visible.

| ID / suggested filename | When | Where to capture | What the image should prove |
|---|---|---|---|
| S1 `01-stack-deployed.png` | After base/bootstrap deployment | AWS CloudFormation → Stacks → relevant stack → Resources / stack status | Resources deployed successfully; show stack names and status, hide account details |
| S2 `02-oidc-trust.png` | After bootstrap | IAM → Roles → GitHub deploy role from bootstrap output → Trust relationships | Exact `repo:Varshx183@207301812/aws-auditguard@1413488585:ref:refs/heads/main`, `sts.amazonaws.com`, and web-identity action; redact provider ARN account ID |
| S3 `03-github-oidc-run.png` | After workflow succeeds | GitHub repository → Actions → Deploy detection with OIDC → successful run → job steps | Validation, OIDC credential step, and deployment succeeded; keep duration visible |
| S4 `04-modified-rule.png` | While modification test is paused | EC2 → Security Groups → newly created `auditguard-modify-test-*` group → Inbound rules | TCP 22 from `0.0.0.0/0` on the disposable test group; optionally pair with Network Interfaces showing no attachment |
| S5 `05-modification-alert.png` | Before pressing Enter to delete test group | Email inbox → AuditGuard SSH notification | `AG-SSH-002`, `ModifySecurityGroupRules`, public CIDR, ports, and `current-rule-state`; redact personal fields |
| S6 `06-failure-retained.png` | After async retries, before replay | CloudShell output of `python3 scripts/failure-lab.py inspect` | Synthetic event ID, failure condition and attempt count; alternatively SQS → processing-failures queue → Monitoring with visible-message count |
| S7 `07-health-alarm.png` | While failure evidence remains | CloudWatch → Alarms → All alarms → filter `aws-auditguard-detection` → errors / processingfailures → History | Real OK→ALARM transition and time; missing data/OK alone is not failure proof |
| S8 `08-cleanup.png` | At the end | GitHub Actions successful `delete` run plus CloudShell base/bucket cleanup output | Detection deletion and recorded cleanup; a GitHub delete run alone does not prove base/bucket removal |
| S9 `09-tests.png` | Anytime after CI succeeds | GitHub Actions → Validate infrastructure → test step | Passing positive/negative, IAM-boundary and replay-retention checks |

For S6, do not delete SQS messages from the console merely to take a screenshot. The replay helper handles only the selected synthetic message. Full SQS bodies may contain account events; the sanitized helper output is preferable for a public portfolio.

Suggested final portfolio selection: S2, S3, S5, S6, S7, and S9. Add a short caption describing exactly what each demonstrates. A synthetic failure screenshot must be labeled **controlled failure exercise**, not a production incident. The previous 147-second measurement applies only to the original creation alarm; do not attach it to new tests.

Save redacted images to `docs/images/` only after review and then link them from the README. This repository currently includes no invented live screenshots.
