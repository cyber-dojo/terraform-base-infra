output "role_name" {
  description = "Github OIDC role name"
  value       = aws_iam_role.this.name
}

output "role_arn" {
  description = "Github OIDC role ARN"
  value       = aws_iam_role.this.arn
}
