module "ecs_cluster" {
  for_each                    = var.ecs_clusters
  source                      = "./ecs-cluster-module"
  env                         = var.env_name
  ecs_cluster_name            = each.key
  aws_region                  = data.aws_region.current.name
  vpc_id                      = module.vpc.vpc_id
  vpc_azs                     = module.vpc.azs
  instance_types_list         = each.value.instance_types_list
  managed_scaling_status      = each.value.managed_scaling_status
  spot_price_vpc_azs          = module.vpc.azs
  asg_service_linked_role_arn = aws_iam_service_linked_role.autoscaling.arn
  asg_vpc_zone_identifier     = [module.vpc.private_subnets[0]]
  ingress_allowed_sg_id       = local.ecs_node_ingress_allowed_sg_id
  ebs_id                      = module.ebs.ebs_id

  docker_gc_grace_period_seconds = 432000

  ecs_cluster_desired_capacity                         = each.value.ecs_cluster_desired_capacity
  ecs_cluster_max_size                                 = each.value.ecs_cluster_max_size
  ecs_cluster_min_size                                 = each.value.ecs_cluster_min_size
  ecs_cluster_on_demand_base_capacity                  = each.value.ecs_cluster_on_demand_base_capacity
  ecs_cluster_on_demand_percentage_above_base_capacity = each.value.ecs_cluster_on_demand_percentage_above_base_capacity

  tags     = local.tags
  asg_tags = local.asg_tags
}

locals {
  ecs_node_ingress_allowed_sg_id = var.ecs_bridge_network_mode ? module.sg_alb.security_group_id : ""
}
