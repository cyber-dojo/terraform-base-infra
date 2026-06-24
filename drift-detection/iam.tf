data "aws_iam_policy_document" "s3_read_allow" {
  statement {
    sid    = "S3Read"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetObject",
    ]
    resources = [
      "arn:aws:s3:::${var.s3_bucket_name}",
      "arn:aws:s3:::${var.s3_bucket_name}/*",
    ]
  }
}

data "aws_iam_policy_document" "ssm_read_allow" {
  statement {
    sid    = "SSMRead"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
    ]
    resources = [
      local.kosli_api_token_ssm_parameter_arn,
    ]
  }
}

data "aws_iam_policy_document" "kms_decrypt_allow" {
  statement {
    sid    = "KMSDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      var.kosli_api_token_kms_key_arn,
    ]
  }
}

data "aws_iam_policy_document" "combined" {
  source_policy_documents = [
    data.aws_iam_policy_document.s3_read_allow.json,
    data.aws_iam_policy_document.ssm_read_allow.json,
    data.aws_iam_policy_document.kms_decrypt_allow.json,
  ]
}
