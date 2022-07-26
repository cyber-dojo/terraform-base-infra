data "aws_caller_identity" "current" {}

data "aws_canonical_user_id" "current" {}

data "aws_ssm_parameter" "amazon_linux_ecs" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"
}
