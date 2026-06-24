module "tf_statefile_paths_reporter" {
  source = "./drift-detection"

  name                   = "terraform-statefile-paths-reporter"
  env                    = var.env_name
  kosli_environment_name = "terraform-drift-detection-${var.env_name}"
  kosli_host             = var.kosli_api_host
  kosli_cli_version      = "v2.18.0"
  kosli_org              = "cyber-dojo"
  schedule_expression    = var.drift_detection_schedule
  s3_bucket_name         = local.state_bucket_name
}
