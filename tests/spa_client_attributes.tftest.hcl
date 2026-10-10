# Plan-only tests for the SPA client's attribute write permissions (flo#2571).
# Run: terraform init -backend=false && terraform test
# The AWS provider is mocked, so no credentials or real resources are needed.

mock_provider "aws" {}

variables {
  name          = "flo-test"
  domain_prefix = "flomenco-test"
  callback_urls = ["https://example.test/auth/callback"]
  logout_urls   = ["https://example.test/"]
}

run "spa_client_has_an_explicit_write_list" {
  command = plan

  # Unset write_attributes means every standard and custom attribute is
  # user-writable through UpdateUserAttributes.
  assert {
    condition     = length(aws_cognito_user_pool_client.spa.write_attributes) > 0
    error_message = "The SPA client must set write_attributes explicitly."
  }

  assert {
    condition = toset(aws_cognito_user_pool_client.spa.write_attributes) == toset([
      "email", "name", "given_name", "family_name", "picture",
    ])
    error_message = "SPA write_attributes must be exactly the profile attributes the app and the IdPs write."
  }
}

run "users_cannot_write_custom_attributes" {
  command = plan

  assert {
    condition = length([
      for a in aws_cognito_user_pool_client.spa.write_attributes : a if startswith(a, "custom:")
    ]) == 0
    error_message = "No custom:* attribute (custom:role, custom:primary_org_id) may be user-writable."
  }

  assert {
    condition     = !contains(aws_cognito_user_pool_client.spa.write_attributes, "email_verified")
    error_message = "Cognito rejects email_verified in WriteAttributes; listing it fails the apply."
  }
}

run "google_mapped_attributes_stay_writable" {
  command = plan

  variables {
    enable_google        = true
    google_client_id     = "test.apps.googleusercontent.com"
    google_client_secret = "test-secret"
  }

  # Cognito skips a mapped attribute the client can't write. username is not
  # an attribute and email_verified can't be listed (see user_pool.tf).
  assert {
    condition = length(setsubtract(
      setsubtract(keys(aws_cognito_identity_provider.google[0].attribute_mapping), ["username", "email_verified"]),
      aws_cognito_user_pool_client.spa.write_attributes,
    )) == 0
    error_message = "Every Google-mapped attribute must be in the SPA client's write_attributes."
  }

  assert {
    condition = length([
      for a in aws_cognito_user_pool_client.spa.write_attributes : a if startswith(a, "custom:")
    ]) == 0
    error_message = "Enabling Google must not widen the write list."
  }
}

run "tenant_sso_mapped_attributes_stay_writable" {
  command = plan

  # identity-service FIXED_ATTRIBUTE_MAPPING (src/lib/sso/cognito-idp.ts) maps
  # email, email_verified, name and username for every tenant IdP it creates
  # at runtime. Keep this list in step with that map.
  assert {
    condition = length(setsubtract(
      ["email", "name"],
      aws_cognito_user_pool_client.spa.write_attributes,
    )) == 0
    error_message = "Tenant SSO maps email and name; the SPA client must keep them writable."
  }
}
