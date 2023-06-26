locals {
  principals_identifiers = setunion(data.aws_iam_roles.roles_admin.arns)
}

data "aws_iam_roles" "roles_admin" {
  name_regex  = "AWSReservedSSO_Admin.*"
  path_prefix = "/aws-reserved/sso.amazonaws.com/"
}

data "aws_iam_policy_document" "kms_main" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.id}:role/OrganizationAccountAccessRole"]
    }
    actions = [
      "kms:*"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Allow access for Key Administrators"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = local.principals_identifiers
    }
    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Allow use of the key"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = local.principals_identifiers
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Allow read key in github pipelines"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [module.oidc_base_infra_role.role_arn]
    }
    actions = [
      "kms:Describe*",
      "kms:Get*",
      "kms:List*"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Allow attachment of persistent resources"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = local.principals_identifiers
    }
    actions = [
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant"
    ]
    resources = [
      "*"
    ]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}
