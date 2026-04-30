#------------------------------------------------------------------------------
# User pool
#
# Email-based, verified. Self-signup enabled — orgs are entered via the app's
# "create org" flow after first login, which writes to org_memberships.
# The pre-token-generation Lambda attaches to this pool (configured below).
#------------------------------------------------------------------------------

resource "aws_cognito_user_pool" "this" {
  name = local.name_prefix

  deletion_protection = var.deletion_protection

  # Users sign in with email. Email must be verified.
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  password_policy {
    minimum_length                   = var.password_minimum_length
    require_uppercase                = true
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = var.password_require_symbols
    temporary_password_validity_days = 3
  }

  mfa_configuration = var.mfa_configuration

  dynamic "software_token_mfa_configuration" {
    for_each = var.mfa_configuration != "OFF" ? [1] : []
    content {
      enabled = true
    }
  }

  # Email: Cognito default transport day one (50/day, unauthenticated From
  # address). For any real traffic, swap to SES — this is configured
  # out-of-band via aws_cognito_user_pool.email_configuration in a follow-up
  # once the SES identity + DKIM are ready.
  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  # Account recovery via verified email only. Don't fall back to phone
  # unless SMS is actually configured — the default here leaks the failure
  # mode as "try your phone" when there is no phone on file.
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  admin_create_user_config {
    allow_admin_create_user_only = false

    invite_message_template {
      email_subject = "You've been invited to ${local.name_prefix}"
      email_message = "Your username is {username} and temporary password is {####}."
      sms_message   = "Your username is {username} and temporary password is {####}."
    }
  }

  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_subject        = "Verify your email for ${local.name_prefix}"
    email_message        = "Your verification code is {####}."
  }

  # Pre-token-generation V2 gives us arrays/objects in claims (vs V1's
  # string-only limitation). org_memberships lands as a real JSON array
  # at the JWT root — no string parsing on the consumer side.
  #
  # Post-confirmation writes the user's initial personal-org membership to
  # DynamoDB so that pre_token_generation always has a primary_org_id to
  # inject on the very first login.
  lambda_config {
    pre_token_generation_config {
      lambda_arn     = aws_lambda_function.pre_token_generation.arn
      lambda_version = "V2_0"
    }

    post_confirmation = aws_lambda_function.post_confirmation.arn
  }

  # Custom attributes users can self-set. Intentionally minimal — the
  # source of truth for org membership is the memberships DDB table, not
  # a user attribute, because membership is many-to-many and mutable.
  schema {
    name                     = "primary_org_id"
    attribute_data_type      = "String"
    mutable                  = true
    required                 = false
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 1
      max_length = 64
    }
  }

  tags = var.tags
}

#------------------------------------------------------------------------------
# Hosted UI domain
#
# Default Cognito domain day one. Custom domain (auth.dev.flomenco.com)
# is an opt-in via var.custom_domain + a pre-provisioned ACM cert in
# us-east-1 (required by Cognito regardless of the pool's region).
#------------------------------------------------------------------------------

resource "aws_cognito_user_pool_domain" "default" {
  count = var.custom_domain == null ? 1 : 0

  domain       = var.domain_prefix
  user_pool_id = aws_cognito_user_pool.this.id
}

resource "aws_cognito_user_pool_domain" "custom" {
  count = var.custom_domain != null ? 1 : 0

  domain          = var.custom_domain
  certificate_arn = var.custom_domain_certificate_arn
  user_pool_id    = aws_cognito_user_pool.this.id
}

#------------------------------------------------------------------------------
# SPA client
#
# Authorization code flow with PKCE — the only safe OAuth flow for a SPA.
# No client secret (public client).
#------------------------------------------------------------------------------

resource "aws_cognito_user_pool_client" "spa" {
  name         = "${local.name_prefix}-spa"
  user_pool_id = aws_cognito_user_pool.this.id

  generate_secret = false

  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["openid", "email", "profile"]

  supported_identity_providers = concat(
    ["COGNITO"],
    var.enable_google ? ["Google"] : []
  )

  # Short access token, longer refresh. SPA refreshes the access token
  # silently; the refresh token lives in a secure store on the client.
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  access_token_validity  = var.access_token_validity_minutes
  id_token_validity      = var.id_token_validity_minutes
  refresh_token_validity = var.refresh_token_validity_days

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH", # SRP for email/password; required by amplify-auth
  ]

  prevent_user_existence_errors = "ENABLED"

  # Enable token revocation so compromised refresh tokens can be
  # invalidated server-side via RevokeToken.
  enable_token_revocation = true

  # The Google IdP must exist before the client references it — Terraform
  # infers this from the supported_identity_providers list, but making
  # the dependency explicit avoids create-time race conditions.
  depends_on = [
    aws_cognito_identity_provider.google,
  ]
}
