module "ecs_cluster" {
  for_each                    = var.ecs_clusters
  source                      = "./ecs-cluster-module"
  env                         = var.env_name
  ecs_cluster_name            = each.key
  aws_region                  = data.aws_region.current.name
  vpc_id                      = module.vpc.vpc_id
  vpc_azs                     = module.vpc.azs
  instance_types_list         = each.value.instance_types_list
  managed_scaling_status      = each.value.managed_scaling_status
  spot_price_vpc_azs          = module.vpc.azs
  asg_service_linked_role_arn = aws_iam_service_linked_role.autoscaling.arn
  asg_vpc_zone_identifier     = [module.vpc.private_subnets[0]]
  ingress_allowed_sg_id       = local.ecs_node_ingress_allowed_sg_id
  ebs_id                      = module.ebs.ebs_id
  ebs_root_size               = var.ebs_root_size
  ebs_root_type               = var.ebs_root_type
  ecs_exec_kms_key_id         = aws_kms_key.kms_ecs_exec_logs.key_id
  ecs_exec_s3_bucket_name     = module.ecs_exec_logs_bucket.s3_bucket_id
  slack_webhook_url           = var.slack_webhook_url

  docker_gc_grace_period_seconds = 432000

  ecs_cluster_desired_capacity                         = each.value.ecs_cluster_desired_capacity
  ecs_cluster_max_size                                 = each.value.ecs_cluster_max_size
  ecs_cluster_min_size                                 = each.value.ecs_cluster_min_size
  ecs_cluster_on_demand_base_capacity                  = each.value.ecs_cluster_on_demand_base_capacity
  ecs_cluster_on_demand_percentage_above_base_capacity = each.value.ecs_cluster_on_demand_percentage_above_base_capacity

  tags     = local.tags
  asg_tags = local.asg_tags
}

locals {
  ecs_node_ingress_allowed_sg_id = var.ecs_bridge_network_mode ? module.sg_alb.security_group_id : ""
}

# KMS key to encrypt ECS exec logs
resource "aws_kms_key" "kms_ecs_exec_logs" {
  description              = "S3 Bucket for ECS exec logs"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  policy                   = data.aws_iam_policy_document.kms_main.json
  deletion_window_in_days  = 30
  enable_key_rotation      = false
  tags                     = local.tags
}

resource "aws_kms_alias" "kms_ecs_exec_logs" {
  target_key_id = aws_kms_key.kms_ecs_exec_logs.key_id
  name          = "alias/ecs_exec_logs"
}

# S3 bucket to store terraform state file
locals {
  ecs_exec_logs_bucket_name = format("ecs-exec-logs-%s", sha1(local.environment_id))
}

module "ecs_exec_logs_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "3.8.2"

  bucket                   = local.ecs_exec_logs_bucket_name
  control_object_ownership = true
  object_ownership         = "ObjectWriter"

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      bucket_key_enabled = true
      apply_server_side_encryption_by_default = {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.kms_ecs_exec_logs.arn
      }
    }
  }

  // S3 bucket-level Public Access Block configuration
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = local.tags
}

resource "aws_s3_bucket_notification" "ecs_exec_logs_bucket_notification" {
  bucket      = module.ecs_exec_logs_bucket.s3_bucket_id
  eventbridge = true
}

# root EBS high I/O alarm
resource "aws_sns_topic" "ebs_io" {
  name = "ebs_io_alerts"
}

module "ebs_notification_lambda" {
  source  = "terraform-aws-modules/notify-slack/aws"
  version = "6.3.0"

  sns_topic_name   = aws_sns_topic.ebs_io.name
  create_sns_topic = false

  lambda_function_name     = "ebs_io_alerts"
  recreate_missing_package = false

  cloudwatch_log_group_retention_in_days = 1

  slack_webhook_url = var.slack_webhook_url
  slack_channel     = "cyber-dojo-alerts"
  slack_username    = "cloudwatch-reporter"

  lambda_description = "Lambda function which sends cloudwatch EBS alerts to Slack"
  log_events         = true

  tags = module.tags.result
}

resource "aws_cloudwatch_metric_alarm" "ebs_high_io" {
  alarm_name                = "ebs-high-io"
  alarm_description         = "Environment name: ${var.env_name} (${data.aws_caller_identity.current.account_id}). High I/O"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  threshold                 = "150000"
  datapoints_to_alarm       = 1
  treat_missing_data        = "ignore"
  insufficient_data_actions = []
  alarm_actions             = [aws_sns_topic.ebs_io.arn]
  ok_actions                = [aws_sns_topic.ebs_io.arn]
  metric_query {
    id          = "read"
    period      = 0
    return_data = false
    metric {
      dimensions = {
        "VolumeId" = data.aws_ebs_volume.ec2_root.id
      }
      metric_name = "VolumeReadOps"
      namespace   = "AWS/EBS"
      period      = 10
      stat        = "Average"
    }
  }
  metric_query {
    id          = "write"
    period      = 0
    return_data = false
    metric {
      dimensions = {
        "VolumeId" = data.aws_ebs_volume.ec2_root.id
      }
      metric_name = "VolumeWriteOps"
      namespace   = "AWS/EBS"
      period      = 10
      stat        = "Average"
    }
  }
  metric_query {
    expression  = "read+write"
    id          = "sum"
    label       = "Total IOPS"
    period      = 0
    return_data = true
  }
}

data "aws_ebs_volume" "ec2_root" {
  most_recent = true

  filter {
    name   = "volume-type"
    values = [var.ebs_root_type]
  }

  filter {
    name   = "tag:Name"
    values = ["app"]
  }
}