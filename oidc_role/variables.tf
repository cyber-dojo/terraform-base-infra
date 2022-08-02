variable "oidc_repos_list" {
  type = list(string)
}

variable "oidc_provider_arn" {
  type = string
}

variable "role_name" {
  type = string
}

variable "policy_json" {
  type = string
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}
