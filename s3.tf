resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

locals {
  vpc_flow_logs_bucket_name     = format("flow-log-%s", sha1(local.environment_id))
  cli_tool_bucket_name          = format("cli-tool-%s", sha1(local.environment_id))
  terraform_modules_bucket_name = format("terraform-modules-%s", sha1(local.environment_id))
  access_logs_bucket_name       = format("alb-access-logs-%s", sha1(local.environment_id))
}

# VPC flow logs bucket
module "vpc_flow_logs_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "3.8.2"

  bucket        = local.vpc_flow_logs_bucket_name
  acl           = "log-delivery-write"
  attach_policy = true
  policy        = data.aws_iam_policy_document.s3_vpc_flow_logs_bucket.json

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = local.tags
}

data "aws_iam_policy_document" "s3_vpc_flow_logs_bucket" {
  statement {
    sid = "AWSLogDeliveryAclCheck"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions = [
      "s3:GetBucketAcl",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::${local.vpc_flow_logs_bucket_name}"
    ]
  }
  statement {
    sid    = "AWSLogDeliveryWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions = [
      "s3:PutObject"
    ]
    resources = [
      "arn:aws:s3:::${local.vpc_flow_logs_bucket_name}/*"
    ]
    condition {
      test     = "StringEquals"
      values   = ["bucket-owner-full-control"]
      variable = "s3:x-amz-acl"
    }
  }
}

# ALB access logs S3 bucket
module "alb_access_logs_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "3.8.2"

  bucket        = local.access_logs_bucket_name
  acl           = "log-delivery-write"
  force_destroy = "false"

  versioning = {
    enabled    = true
    mfa_delete = false
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  attach_elb_log_delivery_policy = true # Required for ALB logs
  attach_lb_log_delivery_policy  = true # Required for ALB/NLB logs

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = local.tags
}

# S3 for terraform modules
# TODO: remove terraform-modules bucket, switch all Cyber-dojo modules to the Kosli terraform-modules bucket
module "terraform_modules_bucket" {
  count   = var.create_tf_modules_bucket ? 1 : 0
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "3.8.2"

  bucket        = local.terraform_modules_bucket_name
  acl           = "private"
  attach_policy = true
  policy        = data.aws_iam_policy_document.s3_tf_modules.json

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = module.tags.result
}

data "aws_iam_policy_document" "s3_tf_modules" {
  statement {
    sid = "AllowReadFromAllAccounts"
    actions = [
      "s3:Get*",
      "s3:List*"
    ]
    # Allow access to tf modules bucket from other AWS accounts
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::244531986313:root",
        "arn:aws:iam::274425519734:root"
      ]
    }
    resources = [
      "arn:aws:s3:::${local.terraform_modules_bucket_name}",
      "arn:aws:s3:::${local.terraform_modules_bucket_name}/*"
    ]
  }
}
