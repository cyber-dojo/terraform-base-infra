# Enable EBS encryption by default for current AWS account
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_ecs_account_setting_default" "vpc_trunking" {
  name  = "awsvpcTrunking"
  value = "enabled"
}

resource "aws_ecs_account_setting_default" "container_instance_long_arn" {
  name  = "containerInstanceLongArnFormat"
  value = "enabled"
}

resource "aws_ecs_account_setting_default" "service_long_arn" {
  name  = "serviceLongArnFormat"
  value = "enabled"
}

resource "aws_ecs_account_setting_default" "task_long_arn" {
  name  = "taskLongArnFormat"
  value = "enabled"
}

resource "aws_ecs_account_setting_default" "container_insights" {
  name  = "containerInsights"
  value = "enabled"
}

resource "aws_iam_service_linked_role" "autoscaling" {
  aws_service_name = "autoscaling.amazonaws.com"
  description      = "Default Service-Linked Role enables access to AWS Services and Resources used or managed by Auto Scaling"
}

resource "aws_iam_service_linked_role" "spot" {
  aws_service_name = "spot.amazonaws.com"
  description      = "Default EC2 Spot Service Linked Role"
}

resource "aws_iam_service_linked_role" "ecs" {
  aws_service_name = "ecs.amazonaws.com"
  description      = "Role to enable Amazon ECS to manage your cluster."
}

