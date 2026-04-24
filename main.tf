terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Intentionally NO `provider "aws"` block here — callers own provider config
# (region, default_tags, allowed_account_ids, assume_role, etc.). Declaring
# a default provider inside a reusable module triggers "Duplicate provider
# configuration" errors when consumed via Terragrunt.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = var.name # e.g. "flo-dev"

  memberships_table_name = coalesce(
    var.memberships_table_name,
    "${local.name_prefix}-org-memberships"
  )

  lambda_function_name = "${local.name_prefix}-pre-token-generation"

  # cognito_issuer is assembled from known pieces so downstream consumers
  # (AVP, Lambda authorizers) don't have to build it themselves.
  cognito_issuer = "https://cognito-idp.${data.aws_region.current.name}.amazonaws.com/${aws_cognito_user_pool.this.id}"
}
