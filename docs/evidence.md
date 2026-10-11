# Live lab results — October 10, 2026

Evidence basis: AWS CLI output supplied by the project owner during the live lab, plus the owner's confirmation of the alarm email. Raw account logs and personal identifiers are intentionally excluded.

| Check | Result |
|---|---|
| CloudFormation deployment | CLI reported successful stack creation/update |
| CloudTrail logging | IsLogging was true |
| S3 delivery | Latest delivery 18:15:36 UTC; no reported delivery error |
| CloudWatch Logs delivery | Latest delivery 18:15:30 UTC; no reported delivery error |
| Test API action | Successful CreateSecurityGroup at 18:13:39 UTC |
| Recorded resource | CloudWatch event matched the test security group |
| Alarm | OK to ALARM at 18:16:05.726 UTC |
| SNS notification | Owner confirmed receiving alarm details and state change by email |
| Test resource cleanup | DeleteSecurityGroup returned success |
| Raw S3 event inspection | Downloaded compressed JSON contained the test event at 18:13:39 UTC; testGroupMatched was true |
| Stack cleanup | Owner supplied DescribeStacks output reporting the stack did not exist in the queried account/Region |
| Retained bucket cleanup | Owner supplied an empty list from the exact bucket-name lookup |

## Timing

Observed API-event-to-alarm interval: 146.726 seconds, approximately 2 minutes 27 seconds. This is one lab observation, not a service guarantee, benchmark average, or email delivery latency. Exact email arrival time was not measured.

## Security observations and limitations

The trail covers regional management events in one Region. It excludes global service events, other Regions, data events, Insights, and Lake. The alarm detects successful security group creation; it does not determine whether the activity is malicious.

The example JSON in this repository is synthetic. No raw production/account event is published. CloudTrail log file validation was enabled but cryptographic digest validation has not been performed.

## Remaining checks

- Review billing after usage reporting catches up.

## October 11: live ingress detection extension

The owner supplied successful AuthorizeSecurityGroupIngress output for TCP 22 from 0.0.0.0/0 on the disposable group, with script completion at 15:54:22 UTC, followed by successful group deletion. The owner separately confirmed the exact email subject `AuditGuard: world-open SSH rule detected`. This validates AG-SSH-001 end to end. No new detection latency was measured; the script completion timestamp is not the CloudTrail event timestamp. The owner reported permanent deletion afterward, but a resource-by-resource teardown transcript was not supplied for that session.

## Latest additions: live validation pending

OIDC deployment, AG-SSH-002 modification detection, failure queues, health alarms, and synthetic recovery are implemented and covered by offline checks. Do not describe their AWS runtime behavior as verified until the walkthrough and screenshot evidence are completed.
