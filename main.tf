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

  # Sign-in URL for email templates. Falls back to a generic placeholder
  # so templates always have a valid link even without var.app_url.
  signin_url = coalesce(var.app_url, "https://floapp.co")

  # Invite email — HTML when SES is configured (DEVELOPER mode), plain
  # text fallback for COGNITO_DEFAULT (which ignores HTML tags anyway).
  # Cognito requires {username} and {####} placeholders exactly as-is.
  invite_email_html = var.ses_source_arn != null ? <<-HTML
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
    <body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:40px 0;">
        <tr><td align="center">
          <table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">

            <tr><td style="background:#0f0f0f;padding:32px 40px;text-align:center;">
              ${var.logo_url != null ? "<img src=\"${var.logo_url}\" alt=\"Flo\" height=\"36\" style=\"display:block;margin:0 auto;\">" : "<span style=\"color:#ffffff;font-size:24px;font-weight:700;letter-spacing:-0.5px;\">Flo</span>"}
            </td></tr>

            <tr><td style="padding:40px;">
              <h1 style="margin:0 0 16px;font-size:24px;font-weight:600;color:#0f0f0f;">You've been invited to Flo</h1>
              <p style="margin:0 0 24px;font-size:16px;color:#444;line-height:1.6;">
                Someone on your team has invited you to join Flo — the AI-powered media platform.
                Use the credentials below to sign in and set your password.
              </p>

              <table width="100%" cellpadding="0" cellspacing="0" style="background:#f9f9f9;border-radius:8px;padding:24px;margin-bottom:32px;">
                <tr>
                  <td style="font-size:13px;color:#888;padding-bottom:4px;">Username</td>
                </tr>
                <tr>
                  <td style="font-size:16px;font-weight:600;color:#0f0f0f;padding-bottom:16px;">{username}</td>
                </tr>
                <tr>
                  <td style="font-size:13px;color:#888;padding-bottom:4px;">Temporary password</td>
                </tr>
                <tr>
                  <td style="font-size:16px;font-weight:600;color:#0f0f0f;font-family:monospace;">{####}</td>
                </tr>
              </table>

              <table width="100%" cellpadding="0" cellspacing="0">
                <tr><td align="center">
                  <a href="${local.signin_url}" style="display:inline-block;background:#0f0f0f;color:#ffffff;text-decoration:none;font-size:15px;font-weight:600;padding:14px 32px;border-radius:8px;">Sign in to Flo →</a>
                </td></tr>
              </table>

              <p style="margin:32px 0 0;font-size:13px;color:#aaa;line-height:1.6;text-align:center;">
                You'll be prompted to set a new password on first sign-in.<br>
                This temporary password expires in 3 days.
              </p>
            </td></tr>

            <tr><td style="background:#f9f9f9;padding:20px 40px;text-align:center;border-top:1px solid #eee;">
              <p style="margin:0;font-size:12px;color:#bbb;">
                © Flomenco, Inc. · <a href="${local.signin_url}" style="color:#bbb;">floapp.co</a>
              </p>
            </td></tr>

          </table>
        </td></tr>
      </table>
    </body>
    </html>
  HTML
  : "You've been invited to Flo. Your username is {username} and temporary password is {####}. Sign in at ${local.signin_url}"
}
