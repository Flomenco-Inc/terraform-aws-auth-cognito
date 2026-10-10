#------------------------------------------------------------------------------
# Platform admins (flo#2554)
#
# Members of this group hold the platform-plane capabilities the Flo custom
# authorizer maps to it: PLATFORM_ADMIN_GROUP_CAPABILITIES in
# flo/services/custom-authorizer-service/src/permissions.py (today
# platform.catalog:read and platform.catalog:update). Nothing else grants
# those capabilities: not an org or tenant role, not a permission set, not an
# API key.
#
# Membership is exactly var.platform_admin_usernames, set per environment in
# flo-core-services envs/<env>/us-east-1/auth/terragrunt.hcl. A pull request
# with an approval is the only way to add someone, so the PR is the audit
# trail. Never add members in the console or with the CLI.
# Runbook: flo docs/platform-admins.md.
#------------------------------------------------------------------------------

resource "aws_cognito_user_group" "platform_admins" {
  name         = "flo-platform-admins"
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "Flo platform admins: the platform.* capabilities the custom authorizer maps to this group. Membership is managed only by terraform-aws-auth-cognito var.platform_admin_usernames (reviewed PR); never edit it by hand."
}

resource "aws_cognito_user_in_group" "platform_admins" {
  for_each = toset(var.platform_admin_usernames)

  user_pool_id = aws_cognito_user_pool.this.id
  group_name   = aws_cognito_user_group.platform_admins.name
  username     = each.value
}
