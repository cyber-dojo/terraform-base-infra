
variable "ebs_size" {
  type = number
}

variable "ebs_name" {
  type = string
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

variable "ebs_snapshot_retention_period_days" {
  type        = string
  description = "How long to store cdb_data EBS snapshots in days"
}