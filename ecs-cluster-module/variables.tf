variable "aws_region" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "vpc_azs" {
  type = list(string)
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

variable "asg_tags" {
  description = "A map of tags to add to all resources"
  type        = list(any)
  default     = []
}

variable "ingress_allowed_sg_id" {
  description = "ID of the security group which is allowed to access ECS instance"
  type        = string
}

variable "ecs_bridge_network_mode" {
  type    = bool
  default = false
}

variable "instance_types_list" {
  description = "The list of the ECS ec2 instance types"
  type        = list(any)
}

variable "managed_scaling_status" {
  description = "Whether auto scaling is managed by ECS. Valid values are ENABLED and DISABLED."
  type        = string
}

variable "spot_price_vpc_azs" {
  type = list(string)
}

variable "asg_service_linked_role_arn" {
  type = string
}

variable "asg_vpc_zone_identifier" {
  type = list(string)
}

variable "ecs_cluster_name" {
  type = string
}

variable "ecs_cluster_desired_capacity" {
  type = number
}

variable "ecs_cluster_max_size" {
  type = number
}

variable "ecs_cluster_min_size" {
  type = number
}

variable "ecs_cluster_on_demand_base_capacity" {
  type = number
}

variable "ecs_cluster_on_demand_percentage_above_base_capacity" {
  type = number
}

variable "ebs_id" {
  type = string
}

variable "ebs_root_size" {
  type = number
}

variable "monit_version" {
  type    = string
  default = "5.32.0"
}

variable "env" {
  type = string
}

# https://github.com/cloudposse/slack-notifier
variable "slack_notifier_version" {
  type    = string
  default = "0.4.0"
}

variable "slack_webhook_url" {
  type    = string
  default = "https://hooks.slack.com/services/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"
}

variable "docker_gc_grace_period_seconds" {
  type    = number
  default = 432000
}

variable "ecs_exec_kms_key_id" {
  type = string
}

variable "ecs_exec_s3_bucket_name" {
  type = string
}
