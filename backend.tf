locals {
  # The table must have a primary key named LockID.
  # See below for more detail. https://www.terraform.io/docs/backends/types/s3.html#dynamodb_table
  lock_key_id            = "LockID"
  state_key              = "terraform.tfstate"
  environment_id         = "${data.aws_caller_identity.current.id}-${data.aws_region.current.name}"
  state_bucket_name      = format("terraform-state-%s", sha1(local.environment_id))
  state_lock_dynamo_name = format("terraform-state-%s", sha1(local.environment_id))
  logging_bucket_name    = format("access-logs-%s", sha1(local.environment_id))
}

# S3 bucket to store terraform state file
module "state_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "3.2.3"

  bucket = local.state_bucket_name
  acl    = "private"

  versioning = {
    enabled = true
  }

  logging = {
    target_bucket = module.logging_bucket.s3_bucket_id
    target_prefix = local.state_bucket_name
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  // S3 bucket-level Public Access Block configuration
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = module.tags.result
}

resource "aws_dynamodb_table" "state_lock" {
  name           = local.state_lock_dynamo_name
  hash_key       = local.lock_key_id
  read_capacity  = 5
  write_capacity = 5
  billing_mode   = "PROVISIONED"
  attribute {
    name = local.lock_key_id
    type = "S"
  }
  server_side_encryption {
    enabled = true
  }
  tags = module.tags.result
}

# Bucket for access logs
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html
module "logging_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "3.2.3"

  bucket = local.logging_bucket_name
  acl    = "log-delivery-write"

  versioning = {
    enabled = true
  }

  logging = {
    target_bucket = local.logging_bucket_name
    target_prefix = local.logging_bucket_name
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  // S3 bucket-level Public Access Block configuration
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = module.tags.result
}