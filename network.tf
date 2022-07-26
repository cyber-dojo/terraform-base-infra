# Enable traffic from internet to load balancer
module "sg_alb" {
  source              = "terraform-aws-modules/security-group/aws"
  version             = "4.9.0"
  name                = "${local.project_name}-alb"
  description         = "Security group for ALB"
  vpc_id              = module.vpc.vpc_id
  ingress_cidr_blocks = var.alb_ingress_cidr_blocks
  ingress_rules       = ["http-80-tcp", "https-443-tcp"]
  egress_rules        = ["all-all"]
  tags                = local.tags
}

# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html
module "alb" {
  source                      = "terraform-aws-modules/alb/aws"
  version                     = "7.0.0"
  name                        = "${local.project_name}-alb"
  load_balancer_type          = "application"
  vpc_id                      = module.vpc.vpc_id
  subnets                     = module.vpc.public_subnets
  security_groups             = [module.sg_alb.security_group_id]
  listener_ssl_policy_default = "ELBSecurityPolicy-FS-1-2-2019-08"
  access_logs = {
    bucket  = module.alb_access_logs_bucket.s3_bucket_id
    prefix  = format("%s-alb-access-logs", local.project_name)
    enabled = true
  }
  http_tcp_listeners = [
    {
      port        = 80
      protocol    = "HTTP"
      action_type = "redirect"
      redirect = {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  ]
  https_listeners = [
    {
      port            = 443
      protocol        = "HTTPS"
      certificate_arn = aws_acm_certificate.default.arn
      action_type     = "fixed-response"
      fixed_response = {
        content_type = "text/plain"
        message_body = "not found"
        status_code  = "404"
      }
    }
  ]
  enable_deletion_protection = true
  tags                       = local.tags
}

resource "aws_service_discovery_private_dns_namespace" "this" {
  name        = "${local.project_name}.${data.aws_region.current.name}"
  description = "VPC: ${module.vpc.vpc_id}"
  vpc         = module.vpc.vpc_id
}
