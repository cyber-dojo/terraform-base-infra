# Amazon Linux 2023 Upgrade — Pre-Downtime Preparation

Things to do **before** the scheduled downtime window for the AL2 → AL2023 ECS instance upgrade,
to de-risk the cutover. Companion to `AL2023_ROLLOUT_PLAN.md`, which covers the cutover itself.

The Terraform changes live on branch `upgrade-to-amazon-linux-2023`.

## Bucket A — Defensive Terraform changes (on this branch)

These ride along with the AMI swap when Terraform is applied at the downtime window. None of them
affect the running instance before that apply.

- [x] **A1. Protect the data EBS volume from Terraform destruction.** Add
  `lifecycle { prevent_destroy = true }` to `aws_ebs_volume.this` in `ebs/main.tf`. Any future
  `terraform apply` that wants to destroy and recreate the volume will hard-fail until the block is
  intentionally removed. Shipped as commit `2958ae1`.

- [ ] **A2. Make shutdown semantics unambiguous.** Add
  `instance_initiated_shutdown_behavior = "terminate"` to `aws_launch_template.this` in
  `ecs-cluster-module/ecs.tf`. Today the launch template doesn't set this, so the EC2 default
  ("stop") applies; `sudo shutdown -h now` from inside the instance puts it in `stopped` state
  rather than terminating it, and the ASG has to notice-then-terminate. With this set, in-OS
  shutdown terminates directly — fewer state transitions, less ambiguity in the rollout.

- [ ] **A3. Pin the data volume's `DeleteOnTermination=false` explicitly.** Today it relies on the
  AWS CLI default at attach-time, which is correct but implicit. Either pass the flag explicitly in
  `attach_ebs.sh` via a structured `--block-device-mappings` form, or just add a post-attach
  assertion. Low value but defensible.

## Bucket B — AWS-side prep (no code changes)

- [ ] **B1. Confirm the SSM parameter resolves** in both target regions. Make a note of the AMI ID
  to cross-check during rehearsal in bucket C.
  ```
  aws ssm get-parameter \
    --name '/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id'
  ```

- [ ] **B2. Rehearse SSM session-manager access** against the **current** running instance. If SSM
  doesn't work today, it won't work on the new instance either, and you don't want to discover that
  mid-cutover when you're trying to tail `/var/log/user-data.log`.

- [ ] **B3. Record current ECS service desired counts** so the rollout's "back to N" step has a
  target. The rollout reduces them to 0 to quiesce writes; without a record, you'll guess.

- [ ] **B4. Take a manual baseline snapshot of the `/ebs_data` volume now** (i.e. the
  `aws_ebs_volume.this` resource defined in `ebs/main.tf` — not an AMI of the whole instance; the
  root volume is rebuilt on every replacement and holds nothing worth preserving). You'll take
  another immediately before cutover, but having a clean baseline now lets you verify your
  restore-from-snapshot procedure works without time pressure.
  ```
  aws ec2 create-snapshot \
    --volume-id <data-vol-id> \
    --description "AL2023 pre-upgrade baseline $(date -u +%Y%m%d)"
  aws ec2 wait snapshot-completed --snapshot-ids <snap-id>
  ```

- [ ] **B5. Verify DLM has fresh snapshots** of the data volume (last 24h). Confirms the safety net
  is actually running, not silently broken.

## Bucket C — End-to-end rehearsal of the new user-data

Highest-value prep work. Every problem this surfaces is one you'd otherwise hit while the
production volume is detached.

- [ ] **C1. Launch a scratch EC2 instance manually** (outside the ASG) using the AL2023 SSM AMI
  from B1, in the same VPC/subnet, with the same IAM instance profile, and with the rendered
  user-data from this branch.

- [ ] **C2. Point its `VOLUME_ID` at a throwaway volume created from a recent snapshot** of the
  real data volume — **not** the real volume itself.

- [ ] **C3. Watch `/var/log/user-data.log` and confirm**:
  - `IMDS_TOKEN` and `INSTANCE_ID` resolve via IMDSv2.
  - `aws ec2 describe-volumes` works without the `/usr/local/bin/aws` path (i.e. the AWS CLI is on
    `$PATH` on the AL2023 ECS-optimised AMI as expected).
  - The polling loop terminates and the attach succeeds.
  - `mount /dev/nvme1n1 /ebs_data` works. `c5a.xlarge` is Nitro so `nvme1n1` should be correct, but
    verify the filesystem mounts read-write with intact data.
  - The static `monit` binary runs and the systemd unit comes up clean.
  - The CloudWatch agent service is present at the path the script expects, and starts.
  - The ECS agent joins your cluster cleanly (or at least starts without error, if you don't want
    to register it for real).

- [ ] **C4. Tear it down.** Terminate the scratch instance, delete the throwaway volume. Cost: a
  couple of cents and an hour.

## Bucket D — PR hygiene

- [ ] **D1. Open the PR** and let CI run a `terraform plan` against both account/region tfvars.
  The plan should show **only** a launch template version bump plus the bucket-A defensive changes.
  Any other diff is drift worth investigating before the cutover.

- [ ] **D2. Decide where the planning docs live.** `AL2023_ROLLOUT_PLAN.md` and this file are
  currently in the repo root. Decide whether they belong on the branch, in a `docs/` folder, or
  stay local. Doesn't matter functionally — just decide before merge.
