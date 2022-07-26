# Create OIDC provider
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html  
module "oidc" {
  source          = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//github-oidc/v2"
  oidc_repos_list = var.oidc_repos_list
}