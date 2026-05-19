#------------------------------------------------------------------------------
# Pre-signup Lambda — federated account linking
#
# Problem: when a user was invited via AdminCreateUser (native Cognito user,
# sub = X) and then authenticates via Google for the first time, Cognito would
# create a *second* identity (sub = Y). The memberships table row written at
# invite time uses sub X, so the Google login (sub Y) has no memberships and
# the user lands on /pricing.
#
# Solution: this trigger fires before the federated user is created. If the
# incoming email matches an existing native user, it calls
# AdminLinkProviderForUser so all subsequent Google logins reuse the native
# identity (same sub X, same memberships row).
#
# Only deployed when enable_google = true since account linking is only
# meaningful when at least one social provider is configured.
#------------------------------------------------------------------------------

data "archive_file" "pre_signup" {
  count = var.enable_google ? 1 : 0

  type        = "zip"
  source_dir  = "${path.module}/lambda/pre_signup"
  output_path = "${path.module}/.terraform-artifacts/pre_signup.zip"
}

resource "aws_cloudwatch_log_group" "pre_signup" {
  count = var.enable_google ? 1 : 0

  name              = "/aws/lambda/${local.name_prefix}-pre-signup"
  retention_in_days = var.pre_signup_log_retention_days
  tags              = var.tags
}

resource "aws_iam_role" "pre_signup" {
  count = var.enable_google ? 1 : 0

  name = "${local.name_prefix}-pre-signup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

data "aws_iam_policy_document" "pre_signup" {
  count = var.enable_google ? 1 : 0

  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.pre_signup[0].arn}:*"]
  }

  # ListUsers: find existing native user by email attribute.
  # AdminLinkProviderForUser: link the Google identity to the native user.
  # Scoped to all user pools in this account+region to avoid a Terraform cycle:
  # the user pool ARN is not known until after the pool is created, but the pool
  # depends on this Lambda, so referencing aws_cognito_user_pool.this.arn here
  # would create a cycle. The account+region scope is tight enough in practice.
  statement {
    sid    = "AccountLinking"
    effect = "Allow"
    actions = [
      "cognito-idp:ListUsers",
      "cognito-idp:AdminLinkProviderForUser",
    ]
    resources = ["arn:aws:cognito-idp:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:userpool/*"]
  }
}

resource "aws_iam_role_policy" "pre_signup" {
  count = var.enable_google ? 1 : 0

  name   = "inline"
  role   = aws_iam_role.pre_signup[0].id
  policy = data.aws_iam_policy_document.pre_signup[0].json
}

resource "aws_lambda_function" "pre_signup" {
  count = var.enable_google ? 1 : 0

  function_name = "${local.name_prefix}-pre-signup"
  role          = aws_iam_role.pre_signup[0].arn

  filename         = data.archive_file.pre_signup[0].output_path
  source_code_hash = data.archive_file.pre_signup[0].output_base64sha256

  runtime = "python3.12"
  handler = "index.handler"

  memory_size = var.pre_signup_memory_mb
  timeout     = var.pre_signup_timeout_seconds

  environment {
    variables = {
      # USER_POOL_ID is intentionally omitted here: the Cognito trigger event
      # carries event["userPoolId"] at runtime, so injecting it as an env var
      # would create a Terraform cycle (user_pool → lambda → user_pool).
      # The Lambda reads it from the event instead.
      LOG_LEVEL = "INFO"
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [
    aws_cloudwatch_log_group.pre_signup,
    aws_iam_role_policy.pre_signup,
  ]

  tags = var.tags
}

resource "aws_lambda_permission" "cognito_invoke_pre_signup" {
  count = var.enable_google ? 1 : 0

  statement_id  = "AllowCognitoInvokePreSignup"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pre_signup[0].function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn    = aws_cognito_user_pool.this.arn
}
