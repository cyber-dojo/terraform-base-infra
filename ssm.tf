resource "aws_ssm_parameter" "alb_listner_arn" {
  name  = "alb_listner_arn"
  type  = "String"
  value = module.alb.https_listener_arns[0]
}

resource "aws_ssm_parameter" "vpc_id" {
  name  = "vpc_id"
  type  = "String"
  value = module.vpc.vpc_id
}

resource "aws_ssm_parameter" "vpc_private_subnets" {
  name  = "vpc_private_subnets"
  type  = "String"
  value = join(",", module.vpc.private_subnets)
}

resource "aws_ssm_parameter" "vpc_private_cidr_blocks" {
  name  = "vpc_private_cidr_blocks"
  type  = "String"
  value = join(",", module.vpc.private_subnets_cidr_blocks)
}

resource "aws_ssm_parameter" "alb_dns_name" {
  name  = "alb_dns_name"
  type  = "String"
  value = module.alb.lb_dns_name
}

resource "aws_ssm_parameter" "alb_sg_id" {
  name  = "alb_sg_id"
  type  = "String"
  value = module.sg_alb.security_group_id
}

resource "aws_ssm_parameter" "alb_zone_id" {
  name  = "alb_zone_id"
  type  = "String"
  value = module.alb.lb_zone_id
}

resource "aws_ssm_parameter" "oidc_role_arn" {
  name  = "oidc_role_arn"
  type  = "String"
  value = module.oidc.role_arn
}
