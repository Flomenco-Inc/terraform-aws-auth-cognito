#------------------------------------------------------------------------------
# Core naming + tagging
#------------------------------------------------------------------------------

variable "name" {
  description = "Base name for all resources (e.g. \"flo-dev\"). Used as the user pool name, the DynamoDB table name prefix, and the Lambda name."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}[a-z0-9]$", var.name))
    error_message = "name must be lowercase kebab-case, 3-32 chars, start with a letter."
  }
}

variable "tags" {
  description = "Tags applied to every taggable resource. Stacks with provider default_tags."
  type        = map(string)
  default     = {}
}

#------------------------------------------------------------------------------
# User pool shape
#------------------------------------------------------------------------------

variable "password_minimum_length" {
  description = "Minimum password length."
  type        = number
  default     = 12
}

variable "password_require_symbols" {
  description = "Require at least one symbol in passwords. Off by default — we require upper+lower+digits which is already strong, and symbols are the top cause of user friction without meaningful entropy gain at length >=12."
  type        = bool
  default     = false
}

variable "mfa_configuration" {
  description = "One of: OFF, OPTIONAL, ON. Day-one default OFF; flipping OPTIONAL later is non-breaking. ON forces MFA for every user — don't enable without a rollout plan."
  type        = string
  default     = "OFF"

  validation {
    condition     = contains(["OFF", "OPTIONAL", "ON"], var.mfa_configuration)
    error_message = "mfa_configuration must be OFF, OPTIONAL, or ON."
  }
}

variable "deletion_protection" {
  description = "Protect the user pool from accidental destroy. Should be ACTIVE for prd, can be INACTIVE in dev to allow clean teardowns."
  type        = string
  default     = "ACTIVE"

  validation {
    condition     = contains(["ACTIVE", "INACTIVE"], var.deletion_protection)
    error_message = "deletion_protection must be ACTIVE or INACTIVE."
  }
}

#------------------------------------------------------------------------------
# App client (SPA)
#------------------------------------------------------------------------------

variable "callback_urls" {
  description = "Allowed OAuth callback URLs for the SPA client."
  type        = list(string)
}

variable "logout_urls" {
  description = "Allowed OAuth logout URLs for the SPA client."
  type        = list(string)
}

variable "refresh_token_validity_days" {
  description = "Refresh token lifetime in days."
  type        = number
  default     = 30
}

variable "access_token_validity_minutes" {
  description = "Access token lifetime in minutes. Shorter = safer but more token refreshes."
  type        = number
  default     = 60
}

variable "id_token_validity_minutes" {
  description = "ID token lifetime in minutes."
  type        = number
  default     = 60
}

#------------------------------------------------------------------------------
# Hosted UI domain
#------------------------------------------------------------------------------

variable "domain_prefix" {
  description = "Prefix for the default Cognito-hosted domain. Final URL will be <prefix>.auth.<region>.amazoncognito.com. Must be globally unique across AWS."
  type        = string
}

variable "custom_domain" {
  description = "Optional custom domain (e.g. \"auth.dev.flomenco.com\"). If set, an ACM cert in us-east-1 for this domain must exist and be referenced via custom_domain_certificate_arn."
  type        = string
  default     = null
}

variable "custom_domain_certificate_arn" {
  description = "ACM certificate ARN for custom_domain. Must be in us-east-1 (Cognito requirement) regardless of the pool region."
  type        = string
  default     = null
}

#------------------------------------------------------------------------------
# Google federation (optional)
#------------------------------------------------------------------------------

variable "enable_google" {
  description = "Enable the Google identity provider. Set false on first apply — the Cognito domain must exist before you can register its callback URL in Google Cloud Console. Flip true once google_client_id / google_client_secret are populated."
  type        = bool
  default     = false
}

variable "google_client_id" {
  description = "Google OAuth 2.0 Web Application client ID. Only required when enable_google = true."
  type        = string
  default     = null
}

variable "google_client_secret" {
  description = "Google OAuth 2.0 client secret. Only required when enable_google = true. Source from AWS Secrets Manager via terragrunt — never commit."
  type        = string
  default     = null
  sensitive   = true
}

#------------------------------------------------------------------------------
# Org memberships table (DynamoDB)
#------------------------------------------------------------------------------

variable "memberships_table_name" {
  description = "Override DynamoDB table name. Defaults to \"<name>-org-memberships\"."
  type        = string
  default     = null
}

variable "memberships_point_in_time_recovery" {
  description = "Enable PITR on the memberships table. Recommend ON for prd, OFF in dev to reduce cost."
  type        = bool
  default     = true
}

#------------------------------------------------------------------------------
# Pre-token-generation Lambda
#------------------------------------------------------------------------------

variable "pre_token_generation_log_retention_days" {
  description = "CloudWatch log retention for the pre-token-generation Lambda."
  type        = number
  default     = 30
}

variable "pre_token_generation_memory_mb" {
  description = "Memory allocated to the Lambda. 256 is plenty for a DDB read — bump if you add expensive logic."
  type        = number
  default     = 256
}

variable "pre_token_generation_timeout_seconds" {
  description = "Lambda timeout in seconds. Keep low — Cognito fails the login if this trigger exceeds 5s, so the Lambda must finish well under that."
  type        = number
  default     = 4
}
