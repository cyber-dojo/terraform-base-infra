terraform {
  backend "s3" {}
}

provider "aws" {
  alias  = "eu-central-1"
  region = "eu-central-1"
}

provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "eu-north-1"
  region = "eu-north-1"
}

locals {
  project_name = "cyber-dojo"
  vpn_cidr     = "10.78.0.0/16" # 10.78.0.1 - 10.68.255.254
  vpc_cidr     = "10.68.0.0/16" # 10.68.0.1 - 10.68.255.254
  vpc_azs_max  = var.vpc_azs_max
  tags         = module.tags.result
  asg_tags     = module.tags.result_asg_list
}

module "tags" {
  source            = "fivexl/tag-generator/aws"
  version           = "2.0.0"
  prefix            = local.project_name
  terraform_managed = "1"
  terraform_state   = "${local.state_bucket_name}/${local.state_key}"
  environment_name  = var.env_name
  data_owner        = local.project_name
  data_pci          = "0"
  data_phi          = "0"
  data_pii          = "0"
}
