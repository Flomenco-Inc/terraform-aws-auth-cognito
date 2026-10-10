# Plan-only tests for the flo-platform-admins group (flo#2554).
# Run: terraform init -backend=false && terraform test
# The AWS provider is mocked, so no credentials or real resources are needed.

mock_provider "aws" {}

variables {
  name          = "flo-test"
  domain_prefix = "flomenco-test"
  callback_urls = ["https://example.test/auth/callback"]
  logout_urls   = ["https://example.test/"]
}

run "group_exists_with_no_members_by_default" {
  command = plan

  assert {
    condition     = aws_cognito_user_group.platform_admins.name == "flo-platform-admins"
    error_message = "The group name is the authorizer contract (PLATFORM_ADMIN_GROUP in permissions.py)."
  }

  assert {
    condition     = length(aws_cognito_user_in_group.platform_admins) == 0
    error_message = "stg/prd default: nobody is a platform admin unless the reviewed list names them."
  }

  assert {
    condition     = output.platform_admin_group_name == "flo-platform-admins"
    error_message = "The output must expose the group name."
  }
}

run "membership_is_exactly_the_reviewed_list" {
  command = plan

  variables {
    platform_admin_usernames = ["qa-platform-admin@floapp.co"]
  }

  assert {
    condition     = keys(aws_cognito_user_in_group.platform_admins) == ["qa-platform-admin@floapp.co"]
    error_message = "One membership per listed username, and nothing else."
  }

  assert {
    condition     = aws_cognito_user_in_group.platform_admins["qa-platform-admin@floapp.co"].group_name == "flo-platform-admins"
    error_message = "Listed users join flo-platform-admins."
  }
}

run "rejects_duplicate_usernames" {
  command = plan

  variables {
    platform_admin_usernames = ["qa-platform-admin@floapp.co", "qa-platform-admin@floapp.co"]
  }

  expect_failures = [var.platform_admin_usernames]
}

run "rejects_padded_usernames" {
  command = plan

  variables {
    platform_admin_usernames = [" qa-platform-admin@floapp.co"]
  }

  expect_failures = [var.platform_admin_usernames]
}

run "rejects_blank_usernames" {
  command = plan

  variables {
    platform_admin_usernames = [""]
  }

  expect_failures = [var.platform_admin_usernames]
}
