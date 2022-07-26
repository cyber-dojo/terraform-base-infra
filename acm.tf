resource "aws_acm_certificate" "default" {
  domain_name       = var.default_acm_certificate_domain_name
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}
