data "aws_availability_zones" "available" {
  state = "available"
}

# https://docs.aws.amazon.com/vpc/latest/userguide/vpc-getting-started.html
module "vpc" {
  source                         = "terraform-aws-modules/vpc/aws"
  version                        = "3.12.0"
  name                           = local.project_name
  cidr                           = local.vpc_cidr
  azs                            = slice(data.aws_availability_zones.available.names, 0, tonumber(local.vpc_azs_max))
  public_subnets                 = var.vpc_public_subnets
  private_subnets                = var.vpc_private_subnets
  database_subnets               = var.vpc_database_subnets
  enable_dns_hostnames           = true
  enable_dns_support             = true
  enable_nat_gateway             = true
  single_nat_gateway             = var.vpc_single_nat_gateway
  one_nat_gateway_per_az         = var.vpc_one_nat_gateway_per_az
  manage_default_security_group  = true
  default_security_group_name    = "default-${local.project_name}"
  default_security_group_ingress = []
  default_security_group_egress  = []
  enable_flow_log                = true
  flow_log_destination_type      = "s3"
  flow_log_destination_arn       = "arn:aws:s3:::${local.vpc_flow_logs_bucket_name}/${local.project_name}/"
  flow_log_log_format            = "$${flow-direction} $${interface-id} $${account-id} $${action} $${az-id} $${vpc-id} $${version} $${type} $${traffic-path} $${tcp-flags} $${subnet-id} $${sublocation-type} $${sublocation-id} $${start} $${srcport} $${srcaddr} $${region} $${protocol} $${pkt-srcaddr} $${pkt-src-aws-service} $${pkt-dstaddr} $${pkt-dst-aws-service} $${packets} $${log-status} $${instance-id} $${end} $${dstport} $${dstaddr} $${bytes}"
  flow_log_file_format           = "parquet"
  vpc_flow_log_tags = {
    Name = format("vpc-flow-logs-s3-bucket-%s", local.project_name)
  }
  tags = local.tags
}
