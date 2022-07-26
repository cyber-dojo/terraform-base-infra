module "security_group_ecs_instance" {
  source              = "terraform-aws-modules/security-group/aws"
  version             = "4.8.0"
  name                = "ecs-instance-${var.ecs_cluster_name}"
  description         = "ECS instance ${var.ecs_cluster_name}"
  vpc_id              = var.vpc_id
  ingress_cidr_blocks = []
  ingress_rules       = []
  egress_rules        = ["all-all"]
  tags                = var.tags

  ingress_with_source_security_group_id = flatten([var.ingress_allowed_sg_id != "" ? [{ rule = "all-all", source_security_group_id = var.ingress_allowed_sg_id }] : []])
}

resource "aws_iam_role" "ecs_instance" {
  name               = "${var.ecs_cluster_name}-ecs-instance-role"
  path               = "/ecs/"
  assume_role_policy = <<EOF
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["ec2.amazonaws.com"]
      },
      "Effect": "Allow"
    }
  ]
}
EOF
  tags               = var.tags
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.ecs_cluster_name}-ecs-instance-profile"
  role = aws_iam_role.ecs_instance.name
}

data "aws_iam_policy_document" "attach_volume" {

  statement {
    sid = "AllowVolumeAttach"
    actions = [
      "ec2:AttachVolume",
      "ec2:DetachVolume"
    ]
    resources = [
      "arn:aws:ec2:*:*:instance/*",
      "arn:aws:ec2:*:*:volume/*"
    ]
  }
}

resource "aws_iam_policy" "attach_volume" {
  name   = "AllowVolumeAttach"
  policy = data.aws_iam_policy_document.attach_volume.json
  tags   = var.tags
}

locals {
  ecs_instance_role_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role", # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/instance_IAM_role.html
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",                     # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ec2-run-command.html
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",                      # https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/create-iam-roles-for-cloudwatch-agent.html
    aws_iam_policy.attach_volume.arn
  ]
}

resource "aws_iam_role_policy_attachment" "ecs_instance" {
  count      = length(local.ecs_instance_role_policy_arns)
  role       = aws_iam_role.ecs_instance.name
  policy_arn = element(local.ecs_instance_role_policy_arns, count.index)
}

locals {
  ecs_config_sh = templatefile("${path.module}/templates/ecs_config.sh", {
    ECS_CLUSTER                 = var.ecs_cluster_name
    ECS_CONTAINER_INSTANCE_TAGS = jsonencode(var.tags)
  })
  cloudwatch_agent_config_sh = templatefile("${path.module}/templates/amazon-cloudwatch-agent.sh", {})
  attach_ebs_sh = templatefile("${path.module}/templates/attach_ebs.sh", {
    VOLUME_ID = var.ebs_id
  })
}

data "cloudinit_config" "this" {
  gzip          = true
  base64_encode = true
  part {
    content_type = "text/x-shellscript"
    content      = local.attach_ebs_sh
  }
  part {
    content_type = "text/x-shellscript"
    content      = local.ecs_config_sh
  }
  part {
    content_type = "text/x-shellscript"
    content      = local.cloudwatch_agent_config_sh
  }
}
