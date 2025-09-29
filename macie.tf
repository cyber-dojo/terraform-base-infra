locals {
  security_aws_account_id = "628389144512"
}

resource "aws_macie2_account" "this" {}

resource "aws_macie2_invitation_accepter" "this" {
  administrator_account_id = local.security_aws_account_id
  depends_on               = [aws_macie2_account.this]
}
