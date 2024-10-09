env_name                   = "prod"
vpc_single_nat_gateway     = true
vpc_one_nat_gateway_per_az = false
vpc_azs_max                = 2
ecs_bridge_network_mode    = true
ebs_size                   = 200
ebs_root_size              = 60

ebs_snapshot_retention_period_days = 60

ecs_clusters = {
  app = {
    instance_types_list    = ["c5a.xlarge"] # 1-year saving plan for c5a family purchased 09.10.24; hourly commitment $0.21500
    managed_scaling_status = "DISABLED"

    ecs_cluster_desired_capacity                         = 1
    ecs_cluster_max_size                                 = 1
    ecs_cluster_min_size                                 = 0
    ecs_cluster_on_demand_base_capacity                  = 1
    ecs_cluster_on_demand_percentage_above_base_capacity = 100
  }
}
