variable "env_name" {
  type = string
}

variable "vpc_azs_max" {
  type = number
}

variable "vpc_public_subnets" {
  type    = list(any)
  default = ["10.68.32.0/19", "10.68.64.0/19"]
}

variable "vpc_private_subnets" {
  type    = list(any)
  default = ["10.68.128.0/19", "10.68.160.0/19"]
}

variable "vpc_database_subnets" {
  type    = list(any)
  default = ["10.68.225.0/24", "10.68.226.0/24"]
}

variable "vpc_single_nat_gateway" {
  type    = bool
  default = false
}

variable "vpc_one_nat_gateway_per_az" {
  type    = bool
  default = true
}

variable "ecs_clusters" {
  type = map(any)
}

variable "ecs_bridge_network_mode" {
  type    = bool
  default = false
}

variable "ebs_root_type" {
  type    = string
  default = "gp3"
}

variable "oidc_repos_list" {
  type = list(string)
  default = [
    "cyber-dojo/terraform-modules"
  ]
}

variable "default_acm_certificate_domain_name" {
  type    = string
  default = "cyber-dojo.org"
}

variable "alb_ingress_cidr_blocks" {
  type        = list(any)
  description = "A list of cidr blocks allowed to access the application"
  default     = ["0.0.0.0/0"]
}

variable "ebs_size" {
  type    = number
  default = 60
}

variable "ebs_root_size" {
  type    = number
  default = 30
}

variable "ebs_snapshot_retention_period_days" {
  type        = string
  description = "How long to store cdb_data EBS snapshots in days"
  default     = 14
}

variable "create_tf_modules_bucket" {
  type    = bool
  default = false
}

variable "config_record_all_supported" {
  description = "Specifies whether AWS Config records configuration changes for every supported type of regional resource (which includes any new type that will become supported in the future)."
  type        = bool
  default     = true
}

variable "grafana_account_id" {
  type    = string
  default = "855032297737"
}
