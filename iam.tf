data "aws_iam_policy_document" "ci" {
  statement {
    sid    = "S3Write"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]
    resources = [
      "${module.state_bucket.s3_bucket_arn}/*",
      "arn:aws:s3:::terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/*"
    ]
  }
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
    sid    = "SecretManager"
    effect = "Allow"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:GetSecretValue"
    ]
    resources = [
      "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:*"
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
    sid = "OIDCGitHub"
    actions = [
      "iam:ListOpenIDConnectProviderTags",
      "iam:UntagOpenIDConnectProvider",
      "iam:DeleteOpenIDConnectProvider",
      "iam:GetOpenIDConnectProvider",
      "iam:TagOpenIDConnectProvider",
      "iam:CreateOpenIDConnectProvider",
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
    ]
  }
  statement {
    sid    = "SSO"
    effect = "Allow"
    actions = [
      "sso:Get*",
      "sso:List*",
      "sso:Describe*"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Lambda"
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
    sid    = "SNS"
    effect = "Allow"
    actions = [
      "SNS:Get*",
      "SNS:List*",
      "SNS:Describe*"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "EventBridge"
    effect = "Allow"
    actions = [
      "events:Get*",
      "events:Describe*",
      "events:List*"
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
    sid    = "servicediscovery"
    effect = "Allow"
    actions = [
      "servicediscovery:GetNamespace",
      "servicediscovery:ListTagsForResource"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "rds"
    effect = "Allow"
    actions = [
      "rds:DescribeDBSubnetGroups",
      "rds:ListTagsForResource"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "ecs"
    effect = "Allow"
    actions = [
      "ecs:ListAccountSettings",
      "ecs:DeleteCapacityProvider",
      "ecs:DeleteCluster",
      "ecs:Describe*",
      "ecs:PutClusterCapacityProviders",
      "ecs:UpdateCapacityProvider",
      "ecs:UpdateCluster",
      "ecs:UpdateClusterSettings",
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
}

data "aws_iam_policy" "admin" {
  name = "AdministratorAccess"
}

resource "aws_iam_policy" "ci" {
  name        = "ci"
  description = "ci policy"
  policy      = data.aws_iam_policy_document.ci.json
  tags        = module.tags.result
}

# Attach permissions to OIDC role
resource "aws_iam_role_policy_attachment" "app_ci" {
  role = module.oidc.role_name
  #policy_arn = aws_iam_policy.ci.arn
  policy_arn = data.aws_iam_policy.admin.arn
}
