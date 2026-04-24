#------------------------------------------------------------------------------
# User pool
#------------------------------------------------------------------------------

output "user_pool_id" {
  description = "Cognito user pool ID."
  value       = aws_cognito_user_pool.this.id
}

output "user_pool_arn" {
  description = "Cognito user pool ARN. Use as the source_arn when granting Cognito permission to invoke other Lambdas."
  value       = aws_cognito_user_pool.this.arn
}

output "user_pool_endpoint" {
  description = "The pool's endpoint URL (cognito-idp.<region>.amazonaws.com/<pool_id>)."
  value       = aws_cognito_user_pool.this.endpoint
}

#------------------------------------------------------------------------------
# OIDC / JWT — what AVP and Lambda authorizers need
#------------------------------------------------------------------------------

output "oidc_issuer" {
  description = "OIDC issuer URL. Feed this into AVP's oidc_issuer input, API Gateway JWT authorizer, and anywhere else that validates Cognito JWTs."
  value       = local.cognito_issuer
}

output "oidc_audience" {
  description = "OIDC audience = SPA app client ID. AVP accepts a list of audiences; wrap with [] on the consumer side if needed."
  value       = aws_cognito_user_pool_client.spa.id
}

output "jwks_uri" {
  description = "JWKS URI for offline JWT signature verification. AVP and API Gateway discover this automatically from the issuer, but it's exposed here for manual verifiers (e.g. a Go service validating tokens without Cognito SDK)."
  value       = "${local.cognito_issuer}/.well-known/jwks.json"
}

#------------------------------------------------------------------------------
# App client (SPA)
#------------------------------------------------------------------------------

output "spa_client_id" {
  description = "App client ID the SPA uses to initiate OAuth flows. Publish as VITE_COGNITO_CLIENT_ID."
  value       = aws_cognito_user_pool_client.spa.id
}

#------------------------------------------------------------------------------
# Hosted UI
#------------------------------------------------------------------------------

output "hosted_ui_domain" {
  description = "The Cognito hosted UI domain (either default or custom). SPA uses this for OAuth redirects."
  value = (
    var.custom_domain != null
    ? var.custom_domain
    : "${var.domain_prefix}.auth.${data.aws_region.current.name}.amazoncognito.com"
  )
}

output "oauth_authorize_url" {
  description = "Convenience: fully-qualified OAuth authorize endpoint. Publish to the SPA so it doesn't have to assemble this itself."
  value = format(
    "https://%s/oauth2/authorize",
    var.custom_domain != null ? var.custom_domain : "${var.domain_prefix}.auth.${data.aws_region.current.name}.amazoncognito.com",
  )
}

output "oauth_token_url" {
  description = "OAuth token endpoint (for code → token exchange)."
  value = format(
    "https://%s/oauth2/token",
    var.custom_domain != null ? var.custom_domain : "${var.domain_prefix}.auth.${data.aws_region.current.name}.amazoncognito.com",
  )
}

output "oauth_logout_url" {
  description = "OAuth logout endpoint."
  value = format(
    "https://%s/logout",
    var.custom_domain != null ? var.custom_domain : "${var.domain_prefix}.auth.${data.aws_region.current.name}.amazoncognito.com",
  )
}

#------------------------------------------------------------------------------
# Org memberships table
#------------------------------------------------------------------------------

output "memberships_table_name" {
  description = "DynamoDB table name for org memberships. App code writing memberships needs this."
  value       = aws_dynamodb_table.memberships.name
}

output "memberships_table_arn" {
  description = "DynamoDB table ARN. Scope IAM policies against this (plus /index/* for GSI reads)."
  value       = aws_dynamodb_table.memberships.arn
}

#------------------------------------------------------------------------------
# Pre-token-generation Lambda — exposed mainly for debuggability
#------------------------------------------------------------------------------

output "pre_token_generation_function_name" {
  description = "Name of the pre-token-generation Lambda. Useful for targeted log-tailing when debugging claims."
  value       = aws_lambda_function.pre_token_generation.function_name
}
