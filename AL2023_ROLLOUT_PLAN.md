# Amazon Linux 2023 Upgrade — Rollout Plan

Plan for rolling the ECS container instance from the Amazon Linux 2 ECS-optimised AMI onto the
Amazon Linux 2023 ECS-optimised AMI, while preserving the customer data on the attached EBS volume.

The Terraform changes themselves live on branch `upgrade-to-amazon-linux-2023` (three commits:
SSM parameter switch, IMDSv2 metadata call, removal of redundant awscli install).

## Constraints

- **Data loss is not acceptable.** Downtime is acceptable.
- The customer data volume must be reused on the newly-launched instance, not rebuilt.

## Facts that shape the plan

- **Single-instance cluster.** The ASG is sized `min=0, desired=1, max=1` in both
  `244531986313-eu-central-1.tfvars` and `274425519734-eu-central-1.tfvars`. Because `max=1` the ASG
  physically cannot run two instances at once — replacement is serial, not parallel, so there is no
  race for the EBS volume.
- **The data volume survives termination.** It is created as a standalone `aws_ebs_volume` in
  `ebs/main.tf` and attached at runtime by `attach_ebs.sh` via `aws ec2 attach-volume`. That CLI
  defaults `DeleteOnTermination=false`, so on termination the volume detaches and returns to the
  `available` state. Only the root volume (`xvda`, defined in the launch template's
  `block_device_mappings`) is destroyed.
- **The new instance already handles timing.** `attach_ebs.sh` polls `describe-volumes` in an
  unbounded loop until the volume is `available` before attaching. No race, no timeout to tune.
- **Terraform apply alone does not roll the instance.** The ASG has no `instance_refresh` block, so
  applying only bumps the launch template's `latest_version`. The running instance keeps running
  until something terminates it. The `null_resource.remove_scale_in_protection` runs and removes
  scale-in protection from the old instance — that is all.
- **DLM snapshot safety net.** `ebs/main.tf` configures AWS Data Lifecycle Manager to snapshot the
  data volume daily at 23:45 UTC and retain `var.ebs_snapshot_retention_period_days` of them. This
  is a fallback, not a substitute for a fresh pre-rollout snapshot.

## Pre-flight (data safety)

1. **Take a fresh manual snapshot** and wait until it is `completed`. Do not rely on the previous
   night's DLM snapshot — it can be up to 24 hours stale.
   ```
   aws ec2 create-snapshot --volume-id <vol-id> --description "pre-AL2023"
   aws ec2 wait snapshot-completed --snapshot-ids <snap-id>
   ```
2. **Verify `DeleteOnTermination=false`** on the data volume mapping of the currently-running
   instance — this should already be the case, but confirm it:
   ```
   aws ec2 describe-instances --instance-ids <id> \
     --query 'Reservations[].Instances[].BlockDeviceMappings'
   ```
3. **Roll non-prod first.** The two tfvars files map to the two AWS accounts; cycle the non-prod
   account end-to-end and confirm the new instance comes up healthy before touching prod.

## Rollout

1. **`terraform apply`** in the target account. This bumps the launch template version. The running
   instance is not replaced.
2. **Quiesce writes** to the data volume by setting each ECS service's desired count to 0 and
   waiting for tasks to stop. This is the critical step for avoiding data loss: it gives containers
   that write to `/ebs_data` the chance to flush.
   ```
   aws ecs update-service --cluster app --service <svc> --desired-count 0
   aws ecs list-tasks --cluster app          # wait until empty
   ```
3. **Terminate the instance** via the EC2 API rather than `sudo shutdown -h now`:
   ```
   aws ec2 terminate-instances --instance-ids <id>
   ```
   `terminate-instances` sends ACPI shutdown to the OS (clean unmount), then terminates, then the
   volume detaches — one step. `shutdown -h now` works too but takes a more roundabout path: the
   launch template does not set `instance_initiated_shutdown_behavior`, so it defaults to **stop**,
   not terminate. The instance would stop with the volume still attached as `in-use`; the ASG would
   notice it's unhealthy and terminate it, which is when the volume would finally detach. Same end
   state, extra state transition.
4. **Wait for the ASG to launch the replacement.** Because `max=1`, this only begins once the old
   instance is fully terminated. No human action required.
5. **Watch the user-data log on the new instance** via SSM:
   ```
   aws ssm start-session --target <new-id>
   sudo tail -f /var/log/user-data.log
   ```
   Expected sequence: a few iterations of "EBS … is in use, wait 10 seconds…", then attach, then
   mount of `/ebs_data`.
6. **Spot-check the data.** `ls /ebs_data`, check directory sizes against expectations.
7. **Restore ECS service desired counts** to their previous values.

## Rollback

If the new instance fails to come up healthy:

- The data volume is intact and detached (state `available`).
- Revert the SSM parameter change in `ecs-cluster-module/data.tf` (and any other commits from the
  branch) and re-apply Terraform. The next ASG-launched instance will use Amazon Linux 2 again and
  re-attach the same volume.
- Worst case (the volume itself is damaged): create a new volume from the pre-rollout snapshot and
  rewire `module.ebs` to reference it, then proceed.

## Answers to specific questions raised during planning

> Will `sudo shutdown -h now` detach the EBS volume?

Indirectly. It halts the OS (clean unmount of `/ebs_data`) and the instance transitions to
`stopped`, not `terminated`, because the launch template doesn't override the default shutdown
behaviour. The ASG then marks the stopped instance unhealthy and terminates it; that termination
is what detaches the data volume. No data loss, but an unnecessary intermediate state — prefer
`aws ec2 terminate-instances`.

> Will the detach happen in time for the newly-launched instance?

There is no "in time" requirement to meet. With `max_size=1` the ASG cannot launch the replacement
until the old instance is fully gone, and `attach_ebs.sh` waits indefinitely for the volume to
become `available`. The timing is self-synchronising.
