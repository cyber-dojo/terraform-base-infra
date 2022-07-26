module "ebs" {
  source = "./ebs"

  ebs_name = local.project_name
  ebs_size = var.ebs_size

  ebs_snapshot_retention_period_days = var.ebs_snapshot_retention_period_days

  tags = module.tags.result
}
