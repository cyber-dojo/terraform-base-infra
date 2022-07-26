resource "aws_ssm_parameter" "ecs_cluster" {
  name  = "ecs_cluster"
  type  = "String"
  value = aws_ecs_cluster.this.arn
}

resource "aws_ssm_parameter" "ecs_capacity_provider" {
  name  = "ecs_capacity_provider"
  type  = "String"
  value = aws_ecs_capacity_provider.this.name
}

