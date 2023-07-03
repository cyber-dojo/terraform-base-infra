# Create OIDC provider
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html  


#module "oidc" {
#  source          = "s3::https://s3-eu-central-1.amazonaws.com/terraform-modules-dacef8339fbd41ce31c346f854a85d0c74f7c4e8/terraform-modules.zip//github-oidc/v2"
#  oidc_repos_list = ["cyber-dojo/terraform-modules"]
#}


resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  # temp fix, https://github.blog/changelog/2023-06-27-github-actions-update-on-oidc-integration-with-aws/
  # thumbprint_list = data.tls_certificate.github_actions_oidc_provider.certificates[0].sha1_fingerprint
  thumbprint_list = distinct(concat(
    [data.tls_certificate.github_actions_oidc_provider.certificates[0].sha1_fingerprint],
    ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"],
  ))
}

data "tls_certificate" "github_actions_oidc_provider" {

  # Read https://github.blog/changelog/2022-01-13-github-actions-update-on-oidc-based-deployments-to-aws/

  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"

}
