env_name                   = "prod"
vpc_single_nat_gateway     = true
vpc_one_nat_gateway_per_az = false
vpc_azs_max                = 2
ecs_bridge_network_mode    = true
ebs_size                   = 700

ebs_snapshot_retention_period_days = 60

ecs_clusters = {
  app = {
    instance_type          = "c5a.xlarge"
    managed_scaling_status = "DISABLED"

    ecs_cluster_desired_capacity                         = 1
    ecs_cluster_max_size                                 = 1
    ecs_cluster_min_size                                 = 0
    ecs_cluster_on_demand_base_capacity                  = 1
    ecs_cluster_on_demand_percentage_above_base_capacity = 100
  }
}