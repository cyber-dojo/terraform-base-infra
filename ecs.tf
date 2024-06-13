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
data "aws_iam_policy_document" "kms_ecs_exec_logs" {
  source_policy_documents = [data.aws_iam_policy_document.kms_main.json]
  statement {
    sid    = "Enable AWS account"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.id}:root"]
    }
    actions = [
      "kms:*"
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_kms_key" "kms_ecs_exec_logs" {
  description              = "S3 Bucket for ECS exec logs"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  policy                   = data.aws_iam_policy_document.kms_ecs_exec_logs.json
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
