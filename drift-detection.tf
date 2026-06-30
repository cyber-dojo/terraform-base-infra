module "tf_statefile_paths_reporter" {
  source = "./drift-detection"

  name                   = "terraform-statefile-paths-reporter"
  env                    = var.env
  kosli_environment_name = "aws-${var.env}-terraform-drift-detection"
  kosli_host             = var.kosli_api_host
  kosli_cli_version      = "v2.29.0"
  kosli_org              = "cyber-dojo"
  schedule_expression    = var.drift_detection_schedule
  s3_bucket_name         = local.state_bucket_name
}
