# Allow GH actions in the terraform-base-infra repo to check configuration drift
module "terraform_base_infra_policy" {
  source                        = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//iam/policy-combine/v2"
  create_policy                 = false
  state_bucket_arn              = module.state_bucket.s3_bucket_arn
  dynamodb_table_state_lock_arn = aws_dynamodb_table.state_lock.arn
  allowed_actions = [
    "tf_backend",
    "s3_read",
    "s3_write",
    "acm_read",
    "iam_write",
    "ec2",
    "launch_template_update",
    "ecs_write",
    "ssm_read",
    "s3_read",
    "oidc_write",
    "service_discovery_read",
    "rds_read",
    "config_read",
    "kms_read",
    "dlm_read",
    "sns_read",
    "logs_write",
    "lambda_write",
    "cloudwatch_write",
    "macie_write"
  ]
}

data "aws_iam_policy_document" "oidc_terraform_base_infra_additional_policy" {
  statement {
    sid    = "S3PutBucketNotification"
    effect = "Allow"
    actions = [
      "s3:PutBucketNotificationConfiguration"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "SetInstanceProtection"
    effect = "Allow"
    actions = [
      "autoscaling:SetInstanceProtection"
    ]
    resources = [
      "*"
    ]
  }
}

module "oidc_base_infra_role" {
  source            = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//github-oidc/v4"
  role_name         = "gh_base_infra"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  oidc_repos_list   = ["cyber-dojo/terraform-base-infra"]
  oidc_policies_list = [
    module.terraform_base_infra_policy.policy_document_json,
    data.aws_iam_policy_document.oidc_terraform_base_infra_additional_policy.json
  ]
  tags = module.tags.result
}

# Enable access from merkely-environment-reporter repo to deploy Kosli reporters
module "kosli_environment_reporter_policy" {
  source        = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//iam/policy-combine/v2"
  create_policy = false
  allowed_actions = [
    "iam_read",
    "ssm_read",
    "logs_write",
    "lambda_write",
    "eventbridge_write"
  ]
}

data "aws_iam_policy_document" "kosli_environment_reporter_additional_policy" {
  statement {
    sid    = "S3ListBuckets"
    effect = "Allow"
    actions = [
      "s3:ListAllMyBuckets"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "S3Write"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]
    resources = [
      "${module.state_bucket.s3_bucket_arn}/terraform/kosli-environment-reporter*"
    ]
  }
  statement {
    sid    = "S3Read"
    effect = "Allow"
    actions = [
      "s3:GetObject"
    ]
    resources = [
      "arn:aws:s3:::terraform-modules-9d7e951c290ec5bbe6506e0ddb064808764bc636/*"
    ]
  }
  statement {
    sid    = "DynamoDB"
    effect = "Allow"
    actions = [
      "dynamodb:Get*",
      "dynamodb:Describe*",
      "dynamodb:List*",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Lambdawrite"
    effect = "Allow"
    actions = [
      "lambda:RemovePermission",
      "lambda:UpdateFunctionCode",
      "lambda:PublishVersion",
      "lambda:AddPermission"
    ]
    resources = [
      "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:kosli-staging*",
      "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:kosli-prod*"
    ]
  }
}

module "oidc_kosli_environment_reporter_role" {
  source            = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//github-oidc/v4"
  role_name         = "gh_actions_reporter"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  oidc_repos_list   = ["cyber-dojo/kosli-environment-reporter"]
  oidc_policies_list = [
    module.kosli_environment_reporter_policy.policy_document_json,
    data.aws_iam_policy_document.kosli_environment_reporter_additional_policy.json
  ]
  tags = module.tags.result
}

# kosli-envidence-reporter repo
module "kosli_evidence_reporter_policy" {
  source        = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//iam/policy-combine/v2"
  create_policy = false
  allowed_actions = [
    "s3_read",
    "iam_read",
    "ssm_read",
    "logs_write",
    "lambda_read",
    "eventbridge_write"
  ]
}

data "aws_iam_policy_document" "kosli_evidence_reporter_additional_policy" {
  statement {
    sid    = "S3StateWrite"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]
    resources = [
      "${module.state_bucket.s3_bucket_arn}/terraform/kosli-evidence-reporter*"
    ]
  }
  statement {
    sid    = "DynamoDB"
    effect = "Allow"
    actions = [
      "dynamodb:Get*",
      "dynamodb:Describe*",
      "dynamodb:List*",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Lambdawrite"
    effect = "Allow"
    actions = [
      "lambda:RemovePermission",
      "lambda:UpdateFunctionCode",
      "lambda:PublishVersion",
      "lambda:AddPermission"
    ]
    resources = [
      "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:ecs-exec-log-uploader*",
      "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:ecs-exec-user-data-reporter*"
    ]
  }
}

module "oidc_kosli_evidence_reporter_role" {
  source            = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//github-oidc/v4"
  role_name         = "kosli-evidence-reporter"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  oidc_repos_list   = ["cyber-dojo/kosli-evidence-reporter"]
  oidc_policies_list = [
    module.kosli_evidence_reporter_policy.policy_document_json,
    data.aws_iam_policy_document.kosli_evidence_reporter_additional_policy.json
  ]
  tags = module.tags.result
}

# Enable access from terraform-modules repo to upload terraform modules to the s3

data "aws_iam_policy_document" "gh_actions_terraform_modules" {
  count = var.create_tf_modules_bucket ? 1 : 0
  statement {
    sid    = "S3Put"
    effect = "Allow"
    actions = [
      "s3:PutObject"
    ]
    resources = [
      "${module.terraform_modules_bucket[0].s3_bucket_arn}/*"
    ]
  }
}

module "oidc_terraform_modules_role" {
  count             = var.create_tf_modules_bucket ? 1 : 0
  source            = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//github-oidc/v4"
  role_name         = "gh_actions_terraform_modules"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  oidc_policies_list = [
    data.aws_iam_policy_document.gh_actions_terraform_modules[0].json
  ]
  tags            = module.tags.result
  oidc_repos_list = ["cyber-dojo/terraform-modules"]
}

# Enable services deployment for the services repositories
module "oidc_services_policy" {
  source        = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//iam/policy-combine/v2"
  create_policy = false
  allowed_actions = [
    "ecr_push",
    "ecr_pull",
    "ecr_read",
    "service_discovery_read",
    "ecs_write",
    "ec2",
    "acm_read",
    "iam_read",
    "ssm_read",
    "logs_write",
    "s3_read",
    "lambda_write",
    "eventbridge_write",
    "org_read"
  ]
}

data "aws_iam_policy_document" "oidc_services_additional_policy" {
  statement {
    sid    = "S3ListBuckets"
    effect = "Allow"
    actions = [
      "s3:ListAllMyBuckets"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "S3Write"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]
    resources = [
      "${module.state_bucket.s3_bucket_arn}/terraform/creator*",
      "${module.state_bucket.s3_bucket_arn}/terraform/custom-start-points*",
      "${module.state_bucket.s3_bucket_arn}/terraform/dashboard*",
      "${module.state_bucket.s3_bucket_arn}/terraform/differ*",
      "${module.state_bucket.s3_bucket_arn}/terraform/exercises-start-points*",
      "${module.state_bucket.s3_bucket_arn}/terraform/languages-start-points*",
      "${module.state_bucket.s3_bucket_arn}/terraform/nginx*",
      "${module.state_bucket.s3_bucket_arn}/terraform/repler*",
      "${module.state_bucket.s3_bucket_arn}/terraform/runner*",
      "${module.state_bucket.s3_bucket_arn}/terraform/saver*",
      "${module.state_bucket.s3_bucket_arn}/terraform/web*",
      "${module.state_bucket.s3_bucket_arn}/terraform/version-reporter*"
    ]
  }
  statement {
    sid    = "DynamoDB"
    effect = "Allow"
    actions = [
      "dynamodb:Get*",
      "dynamodb:Describe*",
      "dynamodb:List*",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem"
    ]
    resources = [
      "*"
    ]
  }
}

module "oidc_services_role" {
  source            = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//github-oidc/v4"
  role_name         = "gh_actions_services"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  oidc_repos_list = [
    "cyber-dojo/creator",
    "cyber-dojo/custom-start-points",
    "cyber-dojo/dashboard",
    "cyber-dojo/differ",
    "cyber-dojo/exercises-start-points",
    "cyber-dojo/languages-start-points",
    "cyber-dojo/nginx",
    "cyber-dojo/repler",
    "cyber-dojo/runner",
    "cyber-dojo/saver",
    "cyber-dojo/shas",
    "cyber-dojo/web",
    "cyber-dojo/version-reporter",
    "cyber-dojo/versioner",
    "cyber-dojo/aws-prod-co-promotion"
  ]
  oidc_policies_list = [
    module.oidc_services_policy.policy_document_json,
    data.aws_iam_policy_document.oidc_services_additional_policy.json
  ]
  tags = module.tags.result
}

# live-snyk-scans repo

module "oidc_live_snyk_scans_policy" {
  source        = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//iam/policy-combine/v2"
  create_policy = false
  allowed_actions = [
    "ecr_push",
    "ecr_pull",
    "ecr_read"
  ]
}

module "oidc_live_snyk_scans_role" {
  source            = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//github-oidc/v4"
  role_name         = "gh_actions_live_snyk_scans"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  oidc_repos_list = [
    "cyber-dojo/live-snyk-scans"
  ]
  oidc_policies_list = [
    module.oidc_live_snyk_scans_policy.policy_document_json
  ]
  tags = module.tags.result
}
