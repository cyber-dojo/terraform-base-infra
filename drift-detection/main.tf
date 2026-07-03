locals {
  paths_file_name                   = "path.file.${var.env}.yml"
  kosli_api_token_ssm_parameter_arn = var.kosli_api_token_ssm_parameter_arn == "" ? "arn:aws:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/kosli_api_token" : var.kosli_api_token_ssm_parameter_arn
}

data "http" "cli_to_layer_mapping" {
  url = "https://lambda-layer-mapping-ccc19615fd6c05ace42e71c551995458dbdb1be7.s3.eu-central-1.amazonaws.com/lambda_layer_versions.json"
}

locals {
  kosli_cli_layer_arn = jsondecode(data.http.cli_to_layer_mapping.response_body)[var.kosli_cli_version][data.aws_region.current.region]
}

module "reporter_lambda" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.8.0"

  attach_policy_json = true
  policy_json        = data.aws_iam_policy_document.combined.json

  function_name = var.name
  description   = "Runs `kosli snapshot paths` against ${var.kosli_environment_name}"
  handler       = "main.lambda_handler"
  runtime       = "python3.11"

  role_name      = var.name
  timeout        = var.lambda_timeout
  create_package = true
  publish        = true

  # Store the deployment package in S3 rather than reading it from the local,
  # gitignored builds/ directory. On a fresh CI runner (and after the global
  # TF_RECREATE_MISSING_LAMBDA_PACKAGE=false in tf.env) that directory starts
  # empty, so a local filename leaves aws_lambda_function unable to read the
  # zip ("reading ZIP file ...: no such file or directory"). Routing the
  # package through S3 makes it durable, matching poll-ecr-guardduty and the
  # kosli-dev docdb-creds-reporter.
  store_on_s3              = true
  s3_bucket                = module.lambda_package_bucket.s3_bucket_id
  recreate_missing_package = true

  # One-time bootstrap: this lambda was already deployed with a local-filename
  # build, so its null_resource.archive is in state with a frozen trigger
  # (recreate is forced false by tf.env). Adding store_on_s3 introduces an
  # aws_s3_object that needs the zip built once, but the frozen trigger means
  # the build never re-runs. Bumping hash_extra changes the package hash ->
  # changes the archive trigger -> forces the build, writing the zip so the S3
  # object can be created.
  hash_extra = "statefile-paths-reporter-s3-bootstrap"

  layers = [
    local.kosli_cli_layer_arn,
  ]

  source_path = [
    {
      path = "${path.module}/lambda-src"
      commands = [
        ":zip"
      ]
    },
    {
      path = "${path.module}/${local.paths_file_name}"
      commands = [
        ":zip"
      ]
    }
  ]

  environment_variables = {
    KOSLI_ENVIRONMENT_NAME            = var.kosli_environment_name
    KOSLI_HOST                        = var.kosli_host
    KOSLI_ORG                         = var.kosli_org
    KOSLI_API_TOKEN_SSM_PARAMETER_ARN = local.kosli_api_token_ssm_parameter_arn
    S3_BUCKET_NAME                    = var.s3_bucket_name
    PATHS_FILE                        = local.paths_file_name
    MIN_ARTIFACT_AGE_SECONDS          = var.min_artifact_age_seconds
  }

  allowed_triggers = {
    AllowExecutionFromCloudWatchCron = {
      principal  = "events.amazonaws.com"
      source_arn = aws_cloudwatch_event_rule.cron.arn
    }
  }

  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days

  tags = var.tags
}

locals {
  environment_id             = "${data.aws_caller_identity.current.account_id}-${data.aws_region.current.region}"
  lambda_package_bucket_name = format("tf-paths-reporter-pkg-%s", sha1(local.environment_id))
}

module "lambda_package_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "3.8.2"

  bucket           = local.lambda_package_bucket_name
  object_ownership = "ObjectWriter"

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  attach_deny_insecure_transport_policy = true

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = var.tags
}
