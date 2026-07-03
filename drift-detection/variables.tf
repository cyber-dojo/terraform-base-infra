variable "name" {
  type        = string
  description = "The name for the Reporter AWS resources (lambda, role, eventbridge rule)."
}

variable "env" {
  type        = string
  description = "Environment name (e.g. staging, prod, infra-dev). Selects path.file.<env>.yml from this module's directory; the file must exist or terraform plan will fail."
}

variable "kosli_environment_name" {
  type        = string
  description = "The Kosli environment name to snapshot into. The lambda runs `kosli snapshot paths <kosli_environment_name>`."
}

variable "s3_bucket_name" {
  type        = string
  description = "The S3 bucket containing the files to fingerprint. The lambda needs read access to it."
}

variable "kosli_host" {
  type        = string
  default     = "https://app.kosli.com"
  description = "The Kosli endpoint."
}

variable "kosli_org" {
  type        = string
  description = "Kosli organisation name (the value for the cli --org parameter)."
  default     = "kosli"
}

variable "kosli_cli_version" {
  type        = string
  description = "The Kosli cli version, in the format v2.18.0. Used to look up the lambda layer ARN."
  default     = "v2.18.0"
}

variable "schedule_expression" {
  type        = string
  default     = "rate(10 minutes)"
  description = "EventBridge schedule expression that triggers the lambda. E.g. `rate(10 minutes)` or `cron(0 * * * ? *)`."
}

variable "tags" {
  type        = map(string)
  description = "Tags to assign to the reporter AWS resources."
  default     = {}
}

variable "lambda_timeout" {
  type        = number
  default     = 60
  description = "The amount of time the lambda has to run in seconds."
}

variable "cloudwatch_logs_retention_in_days" {
  type        = number
  default     = 7
  description = "The retention period of lambda logs (days)."
}

variable "kosli_api_token_ssm_parameter_arn" {
  type        = string
  description = "ARN of the Kosli API token SSM parameter. If empty, defaults to the `kosli_api_token` parameter in the current account/region."
  default     = ""
}

variable "min_artifact_age_seconds" {
  type        = number
  default     = 180
  description = "Skip the snapshot if any fingerprinted S3 object was modified more recently than this. Guards against reporting a statefile (or drift plan) whose attestation has not landed yet. Must exceed the pipelines' write-to-attest latency and be less than the snapshot schedule interval."
}

variable "kosli_api_token_kms_key_arn" {
  type        = string
  description = "ARN of the KMS key used to encrypt the Kosli API token SSM parameter."
  default     = "*"
}
