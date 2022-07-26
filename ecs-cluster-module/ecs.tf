# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-launch-templates.html
resource "aws_launch_template" "this" {
  name_prefix            = "${var.ecs_cluster_name}-"
  description            = "ecs-lt-${var.ecs_cluster_name}"
  update_default_version = true
  image_id               = data.aws_ssm_parameter.amazon_linux_ecs.value
  instance_type          = var.instance_type
  ebs_optimized          = true
  user_data              = data.cloudinit_config.this.rendered
  tag_specifications {
    resource_type = "instance"
    tags          = { "Name" : var.ecs_cluster_name }
  }
  tag_specifications {
    resource_type = "volume"
    tags          = { "Name" : var.ecs_cluster_name }
  }
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [module.security_group_ecs_instance.security_group_id]
  }
  iam_instance_profile {
    arn = aws_iam_instance_profile.this.arn
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  monitoring {
    enabled = true
  }
  tags = var.tags
}

# Get lowest possible spot price
# https://registry.terraform.io/modules/fivexl/ec2-spot-price/aws/latest
module "ec2_spot_price" {
  source                        = "fivexl/ec2-spot-price/aws"
  version                       = "2.0.0"
  availability_zones_names_list = var.vpc_azs
  instance_types_list           = [var.instance_type]
  custom_price_modifier         = 1.1
  normalization_modifier        = 100
}

# Please uncheck the scale lock-in manually to update the instances in the group. Lambda code is required for automation.
resource "aws_autoscaling_group" "this" {
  name_prefix               = "a-ecs-" # don't use ecs- or aws- here. capacity_provider name can't start with it.
  desired_capacity          = var.ecs_cluster_desired_capacity
  max_size                  = var.ecs_cluster_max_size
  min_size                  = var.ecs_cluster_min_size
  vpc_zone_identifier       = var.asg_vpc_zone_identifier
  health_check_type         = "EC2"
  default_cooldown          = 300
  health_check_grace_period = 180
  termination_policies      = ["OldestLaunchTemplate", "OldestInstance"]
  service_linked_role_arn   = var.asg_service_linked_role_arn
  protect_from_scale_in     = true # required for ecs_capacity_provider managed_termination_protection
  capacity_rebalance        = true
  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.this.id
        version            = aws_launch_template.this.latest_version
      }
      override {
        instance_type = var.instance_type
      }
    }
    instances_distribution {
      on_demand_base_capacity                  = var.ecs_cluster_on_demand_base_capacity                  # how many on-demand
      on_demand_percentage_above_base_capacity = var.ecs_cluster_on_demand_percentage_above_base_capacity # % of on-demand from 0% to 100%
      spot_allocation_strategy                 = "lowest-price"
      spot_max_price                           = module.ec2_spot_price.spot_price_current_max_mod
      spot_instance_pools                      = 10
    }
  }
  lifecycle {
    ignore_changes        = [desired_capacity]
    create_before_destroy = true
  }
  dynamic "tag" {
    for_each = concat(var.asg_tags, [{ key = "AmazonECSManaged", value = "1" }])
    content {
      key                 = tag.value.key
      value               = tag.value.value
      propagate_at_launch = true
    }
  }
}

# Remove scale-in protection for instance-refresh
# https://github.com/aws/containers-roadmap/issues/256
# IAM: autoscaling:SetInstanceProtection, autoscaling:DescribeAutoScalingGroups
# this is run when the launch template is updated, and only then, as specified in the trigger.
resource "null_resource" "remove_scale_in_protection" {
  triggers = {
    launch_template_version = aws_launch_template.this.latest_version
  }
  provisioner "local-exec" {
    command = <<EOF
echo "LaunchTemplateId: ${aws_launch_template.this.id} LaunchTemplateVersion: ${aws_launch_template.this.latest_version}"
for INSTANCE_ID in $(aws autoscaling describe-auto-scaling-groups --region ${var.aws_region} --auto-scaling-group-name ${aws_autoscaling_group.this.name} --query 'AutoScalingGroups[].Instances[?LaunchTemplate.LaunchTemplateId==`${aws_launch_template.this.id}` && LaunchTemplate.Version!=`"${aws_launch_template.this.latest_version}"`].InstanceId' --output text);
do
  echo "Remove scale-in protection from $INSTANCE_ID"
  aws autoscaling set-instance-protection --region ${var.aws_region} --instance-ids $INSTANCE_ID --auto-scaling-group-name ${aws_autoscaling_group.this.name} --no-protected-from-scale-in --output text
done
EOF
  }
}

# https://aws.amazon.com/ru/blogs/containers/deep-dive-on-amazon-ecs-cluster-auto-scaling/
resource "aws_ecs_capacity_provider" "this" {
  name = aws_autoscaling_group.this.name # Forcing new capacity provider name depends on ASG name
  auto_scaling_group_provider {
    auto_scaling_group_arn         = aws_autoscaling_group.this.arn
    managed_termination_protection = var.managed_scaling_status
    managed_scaling {
      maximum_scaling_step_size = 1
      minimum_scaling_step_size = 1
      status                    = var.managed_scaling_status
      target_capacity           = 100
    }
  }
  tags = var.tags
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_ecs_cluster" "this" {
  name = var.ecs_cluster_name
  tags = var.tags
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = var.ecs_cluster_name
  capacity_providers = [aws_ecs_capacity_provider.this.name]

  default_capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.this.name
  }
}