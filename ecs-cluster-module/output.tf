output "ecs_cluster_arn" {
  value = aws_ecs_cluster.this.arn
}

output "ecs_capacity_provider_name" {
  value = aws_ecs_capacity_provider.this.name
}
