env                        = "prod"
env_name                   = "prod"
vpc_single_nat_gateway     = true
vpc_one_nat_gateway_per_az = false
vpc_azs_max                = 2
ecs_bridge_network_mode    = true
ebs_size                   = 400
ebs_root_size              = 120

ebs_snapshot_retention_period_days = 60

ecs_clusters = {
  app = {
    # Upgraded from c5a.xlarge; see C8A_UPGRADE_PLAN.md. The c5a-family saving plan
    # referenced here previously was a 1-year term bought 09.10.24, so it has expired.
    instance_types_list    = ["c8a.xlarge"]
    managed_scaling_status = "DISABLED"

    ecs_cluster_desired_capacity                         = 1
    ecs_cluster_max_size                                 = 1
    ecs_cluster_min_size                                 = 0
    ecs_cluster_on_demand_base_capacity                  = 1
    ecs_cluster_on_demand_percentage_above_base_capacity = 100
  }
}
