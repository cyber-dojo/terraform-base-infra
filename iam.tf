# Allow GH actions in the terraform-base-infra repo to check configuration drift
module "terraform_base_infra_policy" {
  source                        = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//iam/policy-combine/v1"
  create_policy                 = false
  state_bucket_arn              = module.state_bucket.s3_bucket_arn
  dynamodb_table_state_lock_arn = aws_dynamodb_table.state_lock.arn
  allowed_actions = [
    "tf_backend",
    "s3_read",
    "acm_read",
    "iam_read",
    "ec2",
    "ecs_write",
    "ssm_read",
    "s3_read",
    "oidc_write",
    "service_discovery_read",
    "rds_read",
    "config_read",
    "kms_read"
  ]
}

module "oidc_base_infra_role" {
  source            = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//github-oidc/v4"
  role_name         = "gh_base_infra"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  oidc_repos_list   = ["cyber-dojo/terraform-base-infra"]
  oidc_policies_list = [
    module.terraform_base_infra_policy.policy_document_json
  ]
  tags = module.tags.result
}

# Enable access from merkely-environment-reporter repo to deploy Kosli reporters
data "aws_iam_policy_document" "gh_actions_reporter" {
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
    sid = "IAMRO"
    actions = [
      "iam:GetGroup",
      "iam:GetGroupPolicy",
      "iam:GetInstanceProfile",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:GetSAMLProvider",
      "iam:GetUser",
      "iam:GetUserPolicy",
      "iam:ListAccessKeys",
      "iam:ListAttachedGroupPolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListEntitiesForPolicy",
      "iam:ListGroupPolicies",
      "iam:ListGroupsForUser",
      "iam:ListInstanceProfileTags",
      "iam:ListInstanceProfiles",
      "iam:ListInstanceProfilesForRole",
      "iam:ListPolicies",
      "iam:ListPolicyTags",
      "iam:ListPolicyVersions",
      "iam:ListRolePolicies",
      "iam:ListRoleTags",
      "iam:ListSAMLProviderTags",
      "iam:ListServiceSpecificCredentials",
      "iam:ListUserPolicies",
      "iam:ListUserTags",
      "iam:PassRole"
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:group/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:saml-provider/*"
    ]
  }
  statement {
    sid    = "Logs"
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:ListTagsLogGroup",
      "logs:CreateLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteLogGroup"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "SSM"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:DescribeParameters",
      "ssm:ListTagsForResource"
    ]
    resources = [
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*",
      "arn:aws:ssm:${data.aws_region.current.name}::parameter/*"
    ]
  }
  statement {
    sid    = "EventBridge"
    effect = "Allow"
    actions = [
      "events:Get*",
      "events:Describe*",
      "events:List*",
      "events:PutRule"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Lambdaro"
    effect = "Allow"
    actions = [
      "lambda:Get*",
      "lambda:List*",
      "lambda:Describe*"
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

module "oidc_reporter_role" {
  source            = "./oidc_role"
  role_name         = "gh_actions_reporter"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  policy_json       = data.aws_iam_policy_document.gh_actions_reporter.json
  tags              = module.tags.result
  oidc_repos_list   = ["cyber-dojo/kosli-environment-reporter"]
}

# kosli-envidence-reporter repo
data "aws_iam_policy_document" "kosli_evidence_reporter" {
  statement {
    sid    = "S3Read"
    effect = "Allow"
    actions = [
      "s3:List*",
      "s3:Describe*",
      "s3:Get*"
    ]
    resources = [
      "*"
    ]
  }
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
    sid = "IAMRO"
    actions = [
      "iam:GetGroup",
      "iam:GetGroupPolicy",
      "iam:GetInstanceProfile",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:GetSAMLProvider",
      "iam:GetUser",
      "iam:GetUserPolicy",
      "iam:ListAccessKeys",
      "iam:ListAttachedGroupPolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListEntitiesForPolicy",
      "iam:ListGroupPolicies",
      "iam:ListGroupsForUser",
      "iam:ListInstanceProfileTags",
      "iam:ListInstanceProfiles",
      "iam:ListInstanceProfilesForRole",
      "iam:ListPolicies",
      "iam:ListPolicyTags",
      "iam:ListPolicyVersions",
      "iam:ListRolePolicies",
      "iam:ListRoleTags",
      "iam:ListSAMLProviderTags",
      "iam:ListServiceSpecificCredentials",
      "iam:ListUserPolicies",
      "iam:ListUserTags",
      "iam:PassRole"
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:group/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:saml-provider/*"
    ]
  }
  statement {
    sid    = "Logs"
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:ListTagsLogGroup",
      "logs:CreateLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteLogGroup"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "SSM"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:DescribeParameters",
      "ssm:ListTagsForResource"
    ]
    resources = [
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*",
      "arn:aws:ssm:${data.aws_region.current.name}::parameter/*"
    ]
  }
  statement {
    sid    = "EventBridge"
    effect = "Allow"
    actions = [
      "events:Get*",
      "events:Describe*",
      "events:List*",
      "events:PutRule"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Lambdaro"
    effect = "Allow"
    actions = [
      "lambda:Get*",
      "lambda:List*",
      "lambda:Describe*"
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

module "kosli_evidence_reporter_role" {
  source            = "./oidc_role"
  role_name         = "kosli-evidence-reporter"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  policy_json       = data.aws_iam_policy_document.kosli_evidence_reporter.json
  tags              = module.tags.result
  oidc_repos_list   = ["cyber-dojo/kosli-evidence-reporter"]
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
  source            = "./oidc_role"
  role_name         = "gh_actions_terraform_modules"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  policy_json       = data.aws_iam_policy_document.gh_actions_terraform_modules[0].json
  tags              = module.tags.result
  oidc_repos_list   = ["cyber-dojo/terraform-modules"]
}

# Enable services deployment for the services repositories
data "aws_iam_policy_document" "gh_actions_services" {
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
      "${module.state_bucket.s3_bucket_arn}/terraform/shas*",
      "${module.state_bucket.s3_bucket_arn}/terraform/web*",
      "${module.state_bucket.s3_bucket_arn}/terraform/version-reporter*"
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
    sid = "ECR"
    actions = [
      "ecr:*Images",
      "ecr:*LifecyclePolicy",
      "ecr:*Repository",
      "ecr:*RepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListTagsForResource",
      "ecr:PutImageScanningConfiguration",
      "ecr:PutImageTagMutability",
      "ecr:PutImage",
      "ecr:TagResource",
      "ecr:UntagResource",
      "ecr:BatchGetImage",
      "ecr:DescribeRepositories",
      "ecr:InitiateLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:UploadLayerPart",
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload"
    ]
    resources = [
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/*"
    ]
  }
  statement {
    sid = "ECRDescribeRegistry"
    actions = [
      "ecr:DescribeRegistry"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid = "ECRAuth"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:GetRegistryPolicy"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Logs"
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:ListTagsLogGroup",
      "logs:CreateLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteLogGroup"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "SSM"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:DescribeParameters",
      "ssm:ListTagsForResource"
    ]
    resources = [
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*",
      "arn:aws:ssm:${data.aws_region.current.name}::parameter/*"
    ]
  }
  statement {
    sid    = "servicediscovery"
    effect = "Allow"
    actions = [
      "servicediscovery:GetNamespace",
      "servicediscovery:ListNamespaces",
      "servicediscovery:ListTagsForResource",
      "servicediscovery:GetService"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid = "IAMRO"
    actions = [
      "iam:GetGroup",
      "iam:GetGroupPolicy",
      "iam:GetInstanceProfile",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:GetSAMLProvider",
      "iam:GetUser",
      "iam:GetUserPolicy",
      "iam:ListAccessKeys",
      "iam:ListAttachedGroupPolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListEntitiesForPolicy",
      "iam:ListGroupPolicies",
      "iam:ListGroupsForUser",
      "iam:ListInstanceProfileTags",
      "iam:ListInstanceProfiles",
      "iam:ListInstanceProfilesForRole",
      "iam:ListPolicies",
      "iam:ListPolicyTags",
      "iam:ListPolicyVersions",
      "iam:ListRolePolicies",
      "iam:ListRoleTags",
      "iam:ListSAMLProviderTags",
      "iam:ListServiceSpecificCredentials",
      "iam:ListUserPolicies",
      "iam:ListUserTags",
      "iam:PassRole"
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:group/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:saml-provider/*"
    ]
  }
  statement {
    sid    = "ecs"
    effect = "Allow"
    actions = [
      "ecs:Describe*",
      "ecs:RegisterTaskDefinition",
      "ecs:DeregisterTaskDefinition",
      "ecs:CreateService",
      "ecs:UpdateService",
      "ecs:DeleteService"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "ec2"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "ec2:GetEbsEncryptionByDefault",
      "ec2:DescribeVpcAttribute",
      "ec2:DescribeVpcs",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeSpotPriceHistory",
      "ec2:DescribeAddresses",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeRouteTables",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeFlowLogs",
      "ec2:DescribeNatGateways",
      "ec2:DescribeLaunchTemplates",
      "ec2:DescribeLaunchTemplateVersions",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeLifecycleHooks",
      "elasticloadbalancing:Describe*",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:CreateRule",
      "elasticloadbalancing:DeleteRule"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "ACM"
    effect = "Allow"
    actions = [
      "acm:DescribeCertificate",
      "acm:ListTagsForCertificate"
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_iam_policy" "gh_actions_services" {
  name        = "services"
  description = "services"
  policy      = data.aws_iam_policy_document.gh_actions_services.json
}

module "oidc_services_role" {
  source            = "./oidc_role"
  role_name         = "gh_actions_services"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  policy_json       = data.aws_iam_policy_document.gh_actions_services.json
  tags              = module.tags.result
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
    "cyber-dojo/version-reporter"
  ]
}

# snyk_scans repo

data "aws_iam_policy_document" "gh_actions_snyk_scans" {
  statement {
    sid = "ECR"
    actions = [
      "ecr:*Images",
      "ecr:*LifecyclePolicy",
      "ecr:*Repository",
      "ecr:*RepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListTagsForResource",
      "ecr:PutImageScanningConfiguration",
      "ecr:PutImageTagMutability",
      "ecr:PutImage",
      "ecr:TagResource",
      "ecr:UntagResource",
      "ecr:BatchGetImage",
      "ecr:DescribeRepositories",
      "ecr:InitiateLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:UploadLayerPart",
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload"
    ]
    resources = [
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/*"
    ]
  }
  statement {
    sid = "ECRDescribeRegistry"
    actions = [
      "ecr:DescribeRegistry"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid = "ECRAuth"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:GetRegistryPolicy"
    ]
    resources = [
      "*"
    ]
  }
}

module "oidc_snyk_scans_role" {
  source            = "./oidc_role"
  role_name         = "gh_actions_snyk_scans"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  policy_json       = data.aws_iam_policy_document.gh_actions_snyk_scans.json
  tags              = module.tags.result
  oidc_repos_list = [
    "cyber-dojo/snyk_scans"
  ]
}
