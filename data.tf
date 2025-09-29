data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_canonical_user_id" "current" {}

data "aws_ssm_parameter" "slack_webhook_url" {
  name = "slack_webhook_url"
}
