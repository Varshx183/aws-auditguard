# Cleanup

If you deployed the optional SSH detection add-on, first run `bash scripts/cleanup-detection.sh`. It removes detection resources including Lambda, EventBridge, logs, alarms and both failure queues (including messages). Save evidence before deleting. For OIDC deployments, use the GitHub workflow delete operation and then remove bootstrap roles separately as described in `docs/oidc-deployment.md`. Then follow the base-stack steps below.

1. Run `bash scripts/cleanup.sh` with the same `AWS_REGION`, `STACK_NAME`, and AWS profile used for deployment. Record the printed bucket name. This deletes the trail, log group/filter, alarm, SNS resources, and IAM role. The bucket is retained intentionally.
2. Verify the stack is deleted. If deletion fails, inspect CloudFormation events before retrying; do not assume logging has stopped.
3. Remove any leftover `auditguard-test-*` security group in the lab VPC after verifying it belongs to this project.
4. To permanently erase the retained bucket, use the S3 console, verify the exact bucket name and account, empty the bucket, then delete it. Alternatively, run the following only after replacing the placeholder with the bucket recorded in step 1:

```bash
bucket='REPLACE_WITH_RETAINED_LAB_BUCKET'
aws s3 rm "s3://$bucket" --recursive --region "$AWS_REGION"
aws s3api delete-bucket --bucket "$bucket" --region "$AWS_REGION"
```

These commands irreversibly delete audit evidence. The template does not enable bucket versioning; if you enabled it manually, remove versions and delete markers too. Verify deletion and review Billing later, allowing for reporting delay. S3 lifecycle expiration is asynchronous and is not immediate teardown.
