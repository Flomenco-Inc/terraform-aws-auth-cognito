#------------------------------------------------------------------------------
# Pre-token-generation Lambda
#
# Fires on every token mint (login + refresh). Queries org_memberships for
# the caller's user_id and injects two claims at the JWT root:
#
#   - org_memberships: [{ org_id, role }, ...]
#   - primary_org_id:  first membership's org_id (or null)
#
# Uses V2 trigger so we can emit arrays/objects directly — no JSON-string-
# in-a-claim nonsense.
#
# Budget: ~50ms warm, ~400ms cold. Cognito fails logins if this exceeds
# 5s; timeout defaults to 4s for safety margin.
#------------------------------------------------------------------------------

data "archive_file" "pre_token_generation" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/pre_token_generation"
  output_path = "${path.module}/.terraform-artifacts/pre_token_generation.zip"
}

resource "aws_cloudwatch_log_group" "pre_token_generation" {
  name              = "/aws/lambda/${local.lambda_function_name}"
  retention_in_days = var.pre_token_generation_log_retention_days
  tags              = var.tags
}

resource "aws_iam_role" "pre_token_generation" {
  name = "${local.lambda_function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

data "aws_iam_policy_document" "pre_token_generation" {
  # CloudWatch Logs for the function's own log group.
  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "${aws_cloudwatch_log_group.pre_token_generation.arn}:*",
    ]
  }

  # Read + conditional-write against the memberships table + GSI.
  # PutItem is scoped to the table only (not GSIs, which are read-only
  # projections). The Lambda uses a ConditionExpression so it only writes
  # when no membership exists yet — handles federated/social logins (e.g.
  # Google OAuth) where the post_confirmation trigger never fires.
  statement {
    sid    = "ReadMemberships"
    effect = "Allow"
    actions = [
      "dynamodb:Query",
      "dynamodb:GetItem",
    ]
    resources = [
      aws_dynamodb_table.memberships.arn,
      "${aws_dynamodb_table.memberships.arn}/index/*",
    ]
  }

  statement {
    sid    = "ProvisionPersonalOrg"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
    ]
    resources = [
      aws_dynamodb_table.memberships.arn,
    ]
  }
}

resource "aws_iam_role_policy" "pre_token_generation" {
  name   = "inline"
  role   = aws_iam_role.pre_token_generation.id
  policy = data.aws_iam_policy_document.pre_token_generation.json
}

resource "aws_lambda_function" "pre_token_generation" {
  function_name = local.lambda_function_name
  role          = aws_iam_role.pre_token_generation.arn

  filename         = data.archive_file.pre_token_generation.output_path
  source_code_hash = data.archive_file.pre_token_generation.output_base64sha256

  runtime = "python3.12"
  handler = "index.handler"

  memory_size = var.pre_token_generation_memory_mb
  timeout     = var.pre_token_generation_timeout_seconds

  environment {
    variables = {
      MEMBERSHIPS_TABLE = aws_dynamodb_table.memberships.name
      LOG_LEVEL         = "INFO"
    }
  }

  tracing_config {
    mode = "Active"
  }

  # Cognito pool → Lambda wiring happens on the pool side
  # (lambda_config.pre_token_generation_config). We just need the
  # log group created first so the first invocation has somewhere
  # to write logs instead of auto-creating one with default retention.
  depends_on = [
    aws_cloudwatch_log_group.pre_token_generation,
    aws_iam_role_policy.pre_token_generation,
  ]

  tags = var.tags
}

# Allow Cognito to invoke the Lambda. Without this, the pool's
# lambda_config reference is silently ignored at login time and the
# Lambda never fires — the token just mints without custom claims.
resource "aws_lambda_permission" "cognito_invoke" {
  statement_id  = "AllowCognitoInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pre_token_generation.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn    = aws_cognito_user_pool.this.arn
}
