#------------------------------------------------------------------------------
# Google identity provider
#
# Gated on var.enable_google so PR 2 can apply cleanly before Google OAuth
# credentials exist. Sequencing:
#   1. Apply with enable_google = false — creates the pool + Cognito domain.
#   2. Register the Cognito domain's idpresponse URL in Google Cloud Console
#      as an authorized redirect URI.
#   3. Drop client_id + client_secret into AWS Secrets Manager.
#   4. Flip enable_google = true (and wire terragrunt to read the secret)
#      to add this resource.
#------------------------------------------------------------------------------

resource "aws_cognito_identity_provider" "google" {
  count = var.enable_google ? 1 : 0

  user_pool_id  = aws_cognito_user_pool.this.id
  provider_name = "Google"
  provider_type = "Google"

  provider_details = {
    client_id        = var.google_client_id
    client_secret    = var.google_client_secret
    authorize_scopes = "openid email profile"
  }

  # Map Google's claims onto Cognito user attributes. username = sub gives
  # a stable, Google-side-guaranteed unique identifier; email_verified
  # lets Cognito skip its own email verification step when Google has
  # already done it.
  attribute_mapping = {
    email          = "email"
    email_verified = "email_verified"
    given_name     = "given_name"
    family_name    = "family_name"
    picture        = "picture"
    username       = "sub"
  }

  lifecycle {
    precondition {
      condition     = var.google_client_id != null && var.google_client_secret != null
      error_message = "enable_google = true requires google_client_id and google_client_secret."
    }
  }
}
