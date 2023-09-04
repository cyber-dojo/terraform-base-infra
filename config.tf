module "config" {
  source                      = "./config"
  environment_id              = local.environment_id
  config_record_all_supported = var.config_record_all_supported
  logging_bucket_id           = module.logging_bucket.s3_bucket_id
  tags                        = module.tags.result
  providers = {
    aws.us-east-1    = aws.us-east-1
    aws.eu-central-1 = aws.eu-central-1
    aws.eu-north-1   = aws.eu-north-1
  }
}