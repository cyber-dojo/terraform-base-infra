resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github_actions_oidc_provider.certificates[0].sha1_fingerprint]

  lifecycle {
    # thumbprint_list is derived from data.tls_certificate below, which reads the
    # live TLS certificate of token.actions.githubusercontent.com on every plan.
    # GitHub rotates that certificate periodically, so its sha1 fingerprint moves
    # with the rotation rather than with any real config change, and each daily
    # drift-detection `tf plan` flags the new fingerprint as drift.
    #
    # AWS validates GitHub's OIDC tokens for this well-known provider against its
    # trusted root-CA store, not against this stored thumbprint, so a stale value
    # here does not affect authentication: role assumption via this provider keeps
    # working across rotations. Ignore the attribute to stop the false drift.
    #
    # NOTE: This ignore is permanent. If you ever need AWS to hold the current
    # certificate thumbprint again, temporarily remove `thumbprint_list` from
    # ignore_changes below (apply, then add it back), or run
    # `terraform apply -replace` on this resource.
    ignore_changes = [thumbprint_list]
  }
}

data "tls_certificate" "github_actions_oidc_provider" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}
