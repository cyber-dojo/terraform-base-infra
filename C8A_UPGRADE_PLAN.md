# c5a.xlarge → c8a.xlarge Instance Type Upgrade — Plan (production only)

Plan for changing the ECS container instance type from `c5a.xlarge` to `c8a.xlarge` in the
**production** account (`274425519734`, eu-central-1), while preserving the customer data on the
attached EBS volume.

**Beta is deliberately left on `c5a.xlarge`.** Only `274425519734-eu-central-1.tfvars` changes.

Companion to `AL2023_UPGRADE_PREP.md` and `AL2023_ROLLOUT_PLAN.md`, which covered the AMI/OS
migration in June 2026. The mechanics are the same; the surface area is smaller.

## Constraints

- **Data loss is not acceptable.** Downtime is acceptable — the site's owner has agreed the site
  can be taken down.
- The customer data volume must be reused on the newly-launched instance, not rebuilt.
- Beta must not be upgraded.

## The change itself

One line, in the production tfvars file only:

```hcl
# 274425519734-eu-central-1.tfvars
ecs_clusters = {
  app = {
    instance_types_list = ["c8a.xlarge"]
    ...
```

The trailing comment on that line described a c5a-family savings plan bought 2024-10-09 on a 1-year
term, so it expired 2025-10-09 and no longer describes anything. It is replaced in the same commit —
see pre-flight P3.

Run `terraform fmt --recursive` after editing.

### Why merging to `master` is safe for beta

The repo's flow is: merge to `master` → `Beta Apply` runs; merge `master` → `prod` → `Prod Apply`
runs. Each workflow passes its own `environment`, and the `tf` wrapper selects the matching tfvars
file. The Beta apply reads `244531986313-eu-central-1.tfvars`, which this change does not touch, so
landing the commit on `master` produces no launch template change in beta. The upgrade only reaches
real infrastructure at the `master` → `prod` merge.

## Facts that shape the plan

- **Same size, same architecture.** `c8a.xlarge` is 4 vCPU / 8 GiB, identical to `c5a.xlarge`, and
  both are x86-64 AMD. Nothing downstream needs to change: no ECS task CPU/memory reservations, no
  container image rebuilds, and the `linux-x64` monit binary and `slack-notifier_linux_amd64`
  binary pulled by `monit_setup.sh` still run.
- **Both consumers of the list change together.** `var.instance_types_list` feeds both
  `aws_launch_template.this.instance_type` (element 0) and the `override` blocks in the ASG's
  `mixed_instances_policy`. A single apply updates both.
- **Terraform apply alone does not roll the instance.** The ASG has no `instance_refresh` block, so
  the apply creates a new launch template version (`update_default_version = true`) and updates the
  ASG to reference `latest_version`. The running `c5a.xlarge` keeps running until something
  terminates it. Same as the AL2023 rollout.
- **Scale-in protection is stripped automatically.** `null_resource.remove_scale_in_protection`
  triggers on the launch template version change and removes protection from the old instance. We
  don't actually depend on it — `aws ec2 terminate-instances` bypasses ASG scale-in protection
  regardless — but its output in the apply log is a useful confirmation the apply did what we think.
- **The AMI is pinned and will be carried forward.** Since commit `83e3a8a` (2026-07-02) the launch
  template has `lifecycle { ignore_changes = [image_id] }`. Terraform will build the new launch
  template version using the AMI ID already in state — the AL2023 ECS-optimised AMI resolved during
  the 2026-06 apply — not today's SSM `recommended`. That is what we want (one variable at a time),
  but it must be verified still valid: see pre-flight P2.
- **The data volume survives termination.** `aws_ebs_volume.this` in `ebs/main.tf` is standalone,
  carries `prevent_destroy = true`, and is attached at runtime by `attach_ebs.sh` via
  `aws ec2 attach-volume`, which defaults `DeleteOnTermination=false`. Only the root volume
  (`/dev/xvda`, from the launch template's `block_device_mappings`) is destroyed.
- **Timing is self-synchronising.** `max_size = 1` means the ASG physically cannot launch the
  replacement until the old instance is fully terminated, and `attach_ebs.sh` polls
  `describe-volumes` in an unbounded loop until the volume is `available`. No race, no timeout to
  tune.
- **Device naming is unchanged.** `c5a` and `c8a` are both Nitro/NVMe, so the hardcoded
  `mount /dev/nvme1n1 /ebs_data` in `attach_ebs.sh` still holds. Verify with `lsblk` on the new
  instance rather than assuming.
- **The volume is pinned to `eu-central-1a`.** `ebs/main.tf` hardcodes
  `availability_zone = "eu-central-1a"` and the ASG runs in `private_subnets[0]`. Region-level
  availability of `c8a` is not enough — it must be offered in that specific AZ, in the production
  account. See P1.
- **New family, so insufficient-capacity is a real risk.** `c8a` reached GA in December 2025 and
  arrived in Frankfurt in February 2026. With `max_size = 1` and the old instance already gone, an
  Insufficient Capacity Error leaves the site down until capacity frees up. See decision D1.
- **The `ebs_high_io` alarm will be left pointing at a deleted volume.** `data.aws_ebs_volume
  .ec2_root` in `ecs.tf` resolves the *most recent* gp3 volume tagged `Name=app` at plan time and
  bakes its ID into `aws_cloudwatch_metric_alarm.ebs_high_io`. When the instance is replaced the old
  root volume is deleted, so the alarm silently stops reporting (`treat_missing_data = "ignore"`).
  A second apply after the cutover re-points it. See step 10.
- **Pricing is not a like-for-like swap.** See P3.
- **Beta stays on c5a, so the two environments diverge.** This is intended, but it means beta is no
  longer a faithful rehearsal environment for anything instance-type-sensitive. Worth a note in the
  PR that raises beta later, if the upgrade proves out.

## Pre-flight — do these before Thursday

All commands target the production account (`274425519734`), eu-central-1.

- [ ] **P1. Confirm `c8a.xlarge` is offered in `eu-central-1a`,** not merely in `eu-central-1`. AZ
  names map to different physical AZs per account, so a result from any other account does not
  answer this.
  ```
  aws ec2 describe-instance-type-offerings \
    --region eu-central-1 \
    --location-type availability-zone \
    --filters Name=instance-type,Values=c8a.xlarge Name=location,Values=eu-central-1a
  ```
  A non-empty `InstanceTypeOfferings` array is the pass condition. **If this returns empty, stop** —
  the change cannot proceed without also moving the data volume to another AZ, which is a different
  and much larger piece of work.

- [ ] **P2. Confirm the pinned AMI is still registered and supports `c8a`.** Get the AMI ID the new
  launch template version will carry:
  ```
  aws ec2 describe-launch-templates --region eu-central-1 \
    --query 'LaunchTemplates[?starts_with(LaunchTemplateName, `app-`)]
             .[LaunchTemplateId,LatestVersionNumber]'

  aws ec2 describe-launch-template-versions --region eu-central-1 \
    --launch-template-id <lt-id> --versions '$Latest' \
    --query 'LaunchTemplateVersions[].LaunchTemplateData.ImageId' --output text
  ```
  Then check it is still usable:
  ```
  aws ec2 describe-images --region eu-central-1 --image-ids <ami-id> \
    --query 'Images[].[Name,CreationDate,DeprecationTime,State]'
  ```
  Pass conditions: `State` is `available`, and `CreationDate` is after 2025-12-02 (`c8a` GA) so the
  ENA and NVMe drivers in that image know about the hardware. The AL2023 apply was 2026-06, so this
  should pass comfortably. If the AMI has been deregistered, you need to un-pin `image_id` as
  described in the `lifecycle` block's comment — but do that as a **separate change on a different
  day**, not bundled into this one.

- [ ] **P3. Check what a c5a savings commitment currently covers.** The comment this change replaces
  referred to a 1-year plan bought 2024-10-09, which would have expired 2025-10-09 — confirm nothing
  was renewed. An EC2 Instance Savings Plan is locked to an instance *family* and region, so any
  live c5a commitment would be stranded by this change, and c8a would bill at full on-demand.
  ```
  aws savingsplans describe-savings-plans --region us-east-1 --states active
  aws ec2 describe-reserved-instances --region eu-central-1 \
    --filters Name=state,Values=active
  ```
  Also compare the two on-demand rates for eu-central-1 in the AWS pricing calculator before
  committing — c8a is a newer generation and is not necessarily cheaper per hour, only per unit of
  work. This is a "know what you're signing up for" check, not a blocker.

- [ ] **P4. Record current ECS service desired counts,** so step 9 has a target.
  ```
  aws ecs list-services --cluster app --region eu-central-1
  aws ecs describe-services --cluster app --region eu-central-1 \
    --services <svc> [<svc> ...] \
    --query 'services[].[serviceName,desiredCount]' --output table
  ```

- [ ] **P5. Rehearse SSM Session Manager** against the current running production instance. If it
  doesn't work today it won't work on the new instance, and you don't want to find that out while
  `/var/log/user-data.log` is the only thing you want to look at.
  ```
  aws ssm start-session --target <instance-id> --region eu-central-1
  ```

- [ ] **P6. Verify DLM snapshots are fresh** (within the last 24h) for the data volume. Confirms the
  safety net is running, not silently broken.
  ```
  aws ec2 describe-snapshots --owner-ids self --region eu-central-1 \
    --filters Name=volume-id,Values=<data-vol-id> \
    --query 'reverse(sort_by(Snapshots,&StartTime))[:3].[SnapshotId,StartTime,State]' \
    --output table
  ```

- [ ] **P7. Optional but cheap: boot one scratch `c8a.xlarge`.** Launch an instance manually from
  the pinned AMI (P2) in the same VPC/subnet, no ECS registration, no data volume. You are only
  proving the AMI boots on the new hardware and that `lsblk` shows the expected NVMe naming. Ten
  minutes and a few cents. Terminate it afterwards. This is the closest thing to a rehearsal
  available, since beta is staying on c5a.

- [ ] **P8. Read the `Prod Plan` output, not the Beta one.** The PR into `master` runs `Beta Plan`,
  which will show **no** launch template change — that is the correct result and confirms beta is
  untouched. The plan that matters comes from the `master` → `prod` PR, and should show **only**: a
  new `aws_launch_template.this` version (instance_type change), the ASG's `mixed_instances_policy`
  override change, and the `null_resource.remove_scale_in_protection` replacement. Anything else is
  drift worth understanding before Thursday.

## Decisions to make before Thursday

- **D1. Fallback instance type in the override list?** Setting
  `instance_types_list = ["c8a.xlarge", "c5a.xlarge"]` makes the ASG's on-demand allocation
  strategy (`prioritized` by default) try `c8a.xlarge` first and fall back to `c5a.xlarge` on an
  Insufficient Capacity Error, so the site comes back up either way. The cost is that a silent
  fallback is easy to miss — you could believe you're on c8a for weeks when you aren't. Note the
  launch template's own `instance_type` takes element 0, so it would still be `c8a.xlarge`.
  *Recommendation:* ship the fallback for the cutover, verify what actually launched at step 7, and
  drop `c5a.xlarge` from the list in a follow-up PR once you've confirmed c8a came up. If you'd
  rather fail loudly than fall back silently, keep the single-element list as committed and accept
  that an ICE means a longer outage. **As committed, this is the single-element list** — the
  fallback has not been applied.

## Cutover

Downtime starts at step 4 and ends at step 9.

1. **Announce the downtime** to the site's owner and in `#cyber-dojo-alerts`, so the monit and
   CloudWatch alerts that fire during the window aren't mistaken for a real incident.

2. **Take a fresh manual snapshot of the data volume and wait for it to complete.** Do not rely on
   last night's DLM snapshot; it can be up to 24 hours stale.
   ```
   aws ec2 create-snapshot --region eu-central-1 \
     --volume-id <data-vol-id> --description "pre-c8a $(date -u +%Y%m%dT%H%M)"
   aws ec2 wait snapshot-completed --region eu-central-1 --snapshot-ids <snap-id>
   ```

3. **Promote to prod.** Open and merge a PR from `master` into `prod`; the `Prod Apply` workflow
   runs. (The earlier merge into `master` will already have run `Beta Apply` with no launch template
   change — confirm that was the case before promoting.)

   Confirm in the `Prod Apply` log that a new launch template version was created and that
   `remove_scale_in_protection` printed a "Remove scale-in protection from i-…" line. The running
   instance is **not** replaced by this step.

4. **Quiesce writes to the data volume.** This is the step that protects the data — it lets
   containers writing to `/ebs_data` flush and exit cleanly.
   ```
   aws ecs update-service --region eu-central-1 --cluster app --service <svc> --desired-count 0
   # repeat for every service recorded in P4, then wait until empty:
   aws ecs list-tasks --region eu-central-1 --cluster app
   ```

5. **Terminate the instance via the EC2 API** — not `sudo shutdown -h now`. The launch template
   still does not set `instance_initiated_shutdown_behavior` (bucket-A item A2 from the AL2023 prep
   was never shipped), so an in-OS shutdown *stops* rather than terminates, and you'd wait for the
   ASG to notice and terminate it. `terminate-instances` sends ACPI shutdown to the OS for a clean
   unmount, terminates, and detaches the data volume in one step.
   ```
   aws ec2 terminate-instances --region eu-central-1 --instance-ids <old-instance-id>
   aws ec2 wait instance-terminated --region eu-central-1 --instance-ids <old-instance-id>
   ```

6. **Wait for the ASG to launch the replacement.** No human action required — because `max_size=1`
   this only begins once the old instance is fully gone.
   ```
   aws autoscaling describe-auto-scaling-groups --region eu-central-1 \
     --auto-scaling-group-names <asg-name> \
     --query 'AutoScalingGroups[].Instances[].[InstanceId,LifecycleState,InstanceType]' \
     --output table
   ```

7. **Confirm the instance type is what you expect.** This is the step that catches a silent
   fallback to `c5a.xlarge` if you revisit decision D1 before the window.
   ```
   aws ec2 describe-instances --region eu-central-1 --instance-ids <new-instance-id> \
     --query 'Reservations[].Instances[].[InstanceType,ImageId,State.Name]' --output table
   ```

8. **Watch the user-data log and check the mount** via SSM:
   ```
   aws ssm start-session --target <new-instance-id> --region eu-central-1
   sudo tail -f /var/log/user-data.log
   ```
   Expected sequence: a few "EBS vol-… is in use, wait 10 seconds…" iterations, then attach, then
   the `/ebs_data` mount. Then confirm on the box:
   ```
   lsblk                      # nvme0n1 = root, nvme1n1 = data
   mount | grep ebs_data      # mounted rw
   ls /ebs_data               # data present, sizes look right
   df -h /ebs_data
   systemctl status ecs monit amazon-cloudwatch-agent
   ```
   And that ECS sees it:
   ```
   aws ecs list-container-instances --region eu-central-1 --cluster app
   ```

9. **Restore the ECS service desired counts** recorded in P4, wait for tasks to reach `RUNNING` and
   for the ALB target groups to go healthy, then smoke-test the site in a browser. Downtime ends
   here.

10. **Re-apply Terraform to re-point the `ebs_high_io` alarm.** The alarm's `VolumeId` dimension
    still names the root volume of the instance you terminated, which no longer exists.
    `data.aws_ebs_volume.ec2_root` will now resolve to the new root volume, so a plan should show
    exactly one in-place change to `aws_cloudwatch_metric_alarm.ebs_high_io`. Trigger this by
    re-running the `Prod Apply` workflow. Confirm afterwards that the alarm is in `OK` and not
    `INSUFFICIENT_DATA`:
    ```
    aws cloudwatch describe-alarms --region eu-central-1 --alarm-names ebs-high-io \
      --query 'MetricAlarms[].[StateValue,StateUpdatedTimestamp]'
    ```

11. **Post-cutover watch.** Leave it an hour and check `#cyber-dojo-alerts` for monit noise, and
    check CPU/memory in CloudWatch against the pre-change baseline. c8a should show *lower* CPU for
    the same load; a higher figure means something is off.

## Rollback

The data volume is unaffected by any of this — it is standalone, `prevent_destroy`, and returns to
`available` on termination. Rollback is therefore just "put the old instance type back":

1. Revert the tfvars change (`git revert` the commit) and merge to `prod`, so CI applies it. This
   creates another launch template version, back on `c5a.xlarge`.
2. Terminate the c8a instance with `aws ec2 terminate-instances`.
3. The ASG launches a `c5a.xlarge` replacement, which re-attaches the same data volume.

Failure modes and their responses:

- **Insufficient capacity for `c8a.xlarge`** (the ASG cannot launch): run the rollback above; it is
  faster than waiting for AWS capacity. If you took decision D1's fallback before the window, this
  resolves itself onto `c5a.xlarge` instead and you have no outage to manage — just an unsuccessful
  upgrade.
- **Instance launches but user-data fails** (e.g. `/dev/nvme1n1` is not the data volume): SSM onto
  the box and mount by UUID or by the correct device from `lsblk` to restore service, then fix
  `attach_ebs.sh` properly in a follow-up PR. Do not leave a hand-mounted instance running longer
  than the incident — the next replacement won't repeat your manual step.
- **The data volume itself is damaged:** create a new volume from the step-2 snapshot in
  `eu-central-1a`, and rewire `module.ebs` to reference it. Note `prevent_destroy = true` on
  `aws_ebs_volume.this` will hard-fail any plan that wants to destroy the existing volume — that is
  the guard working, and removing it should be a deliberate, reviewed act.
