variable "environment_id" {
  type = string
}

variable "logging_bucket_id" {
  type = string
}

variable "config_record_all_supported" {
  description = "Specifies whether AWS Config records configuration changes for every supported type of regional resource (which includes any new type that will become supported in the future)."
  type        = bool
  default     = true
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}
