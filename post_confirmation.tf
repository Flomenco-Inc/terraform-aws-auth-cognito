#------------------------------------------------------------------------------
# Post-confirmation Lambda
#
# Fires once per user when they confirm their account (email code or admin
# confirmation).  Creates a "personal workspace" org + OWNER membership row
# in the memberships table so that the pre-token-gen Lambda always has a
# real primary_org_id to inject on the first login.
#
# Why here instead of app code?
#   - The membership must exist *before* the first token is minted.  Doing
#     it in app code would require a second round-trip after sign-up.
#   - Idempotent DDB PutItem means repeated triggers are safe.
#
# Required Cognito lambda_config wiring: user_pool.tf sets
#   post_confirmation = aws_lambda_function.post_confirmation.arn
#------------------------------------------------------------------------------

data "archive_file" "post_confirmation" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/post_confirmation"
  output_path = "${path.module}/.terraform-artifacts/post_confirmation.zip"
}

resource "aws_cloudwatch_log_group" "post_confirmation" {
  name              = "/aws/lambda/${local.name_prefix}-post-confirmation"
  retention_in_days = var.post_confirmation_log_retention_days
  tags              = var.tags
}

resource "aws_iam_role" "post_confirmation" {
  name = "${local.name_prefix}-post-confirmation-role"

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

data "aws_iam_policy_document" "post_confirmation" {
  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.post_confirmation.arn}:*"]
  }

  # Write access: PutItem + GetItem to create / idempotency-check memberships.
  statement {
    sid    = "WriteMemberships"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
    ]
    resources = [aws_dynamodb_table.memberships.arn]
  }
}

resource "aws_iam_role_policy" "post_confirmation" {
  name   = "inline"
  role   = aws_iam_role.post_confirmation.id
  policy = data.aws_iam_policy_document.post_confirmation.json
}

resource "aws_lambda_function" "post_confirmation" {
  function_name = "${local.name_prefix}-post-confirmation"
  role          = aws_iam_role.post_confirmation.arn

  filename         = data.archive_file.post_confirmation.output_path
  source_code_hash = data.archive_file.post_confirmation.output_base64sha256

  runtime = "python3.12"
  handler = "index.handler"

  memory_size = var.post_confirmation_memory_mb
  timeout     = var.post_confirmation_timeout_seconds

  environment {
    variables = {
      MEMBERSHIPS_TABLE = aws_dynamodb_table.memberships.name
      LOG_LEVEL         = "INFO"
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [
    aws_cloudwatch_log_group.post_confirmation,
    aws_iam_role_policy.post_confirmation,
  ]

  tags = var.tags
}

# Allow Cognito to invoke this Lambda.  Without this resource-based policy
# Cognito silently skips the trigger — the confirmation succeeds but the
# membership is never written.
resource "aws_lambda_permission" "cognito_invoke_post_confirmation" {
  statement_id  = "AllowCognitoInvokePostConfirmation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.post_confirmation.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn    = aws_cognito_user_pool.this.arn
}
