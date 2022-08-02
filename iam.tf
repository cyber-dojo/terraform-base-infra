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
  count       = var.create_tf_modules_bucket ? 1 : 0
  source = "./oidc_role"
  role_name = "gh_actions_terraform_modules"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  policy_json = data.aws_iam_policy_document.gh_actions_terraform_modules[0].json
  tags = module.tags.result
  oidc_repos_list = ["cyber-dojo/terraform-modules"]
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
      "${module.state_bucket.s3_bucket_arn}/terraform/web*"
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
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/creator",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/custom-start-points",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/dashboard",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/differ",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/exercises-start-points",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/languages-start-points",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/nginx",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/repler",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/runner",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/saver",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/shas",
      "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/web"
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
      "ec2:DescribeRegions",
      "ec2:DescribeAccountAttributes",
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
  source = "./oidc_role"
  role_name = "gh_actions_services"
  oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
  policy_json = data.aws_iam_policy_document.gh_actions_services.json
  tags = module.tags.result
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
    "cyber-dojo/web"
  ]
}
