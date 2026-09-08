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
    # Upgraded from c5a.xlarge; see C8A_UPGRADE_PLAN.md. The c5a-family saving plan this
    # comment used to record expired and was not renewed. Compute is covered by the
    # management account's Compute Savings Plan, which is not locked to an instance family,
    # so there is no per-family commitment to keep in step with this line.
    instance_types_list    = ["c8a.xlarge"]
    managed_scaling_status = "DISABLED"

    ecs_cluster_desired_capacity                         = 1
    ecs_cluster_max_size                                 = 1
    ecs_cluster_min_size                                 = 0
    ecs_cluster_on_demand_base_capacity                  = 1
    ecs_cluster_on_demand_percentage_above_base_capacity = 100
  }
}
