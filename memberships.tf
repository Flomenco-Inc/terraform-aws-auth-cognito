#------------------------------------------------------------------------------
# Org memberships (DynamoDB)
#
# Source of truth for "which orgs does user X belong to, and in what role."
# Read on every token mint by the pre-token-generation Lambda.
#
# Access patterns:
#   - list orgs for a user (hot path, every login)
#     → Query PK = user_id
#   - list members of an org (admin UX)
#     → Query GSI1 PK = org_id
#
# Writes happen from app code (org creation, invite acceptance, role
# changes). The module intentionally does NOT wire a writer — that's app
# concern, not infra concern.
#------------------------------------------------------------------------------

resource "aws_dynamodb_table" "memberships" {
  name         = local.memberships_table_name
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "user_id"
  range_key = "org_id"

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "org_id"
    type = "S"
  }

  global_secondary_index {
    name            = "by-org"
    hash_key        = "org_id"
    range_key       = "user_id"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = var.memberships_point_in_time_recovery
  }

  # Deletion protection on DDB is separately named + not the same API as
  # Cognito's. Follow the pool's choice so a "safe to nuke" dev setup is
  # consistent across both.
  deletion_protection_enabled = var.deletion_protection == "ACTIVE"

  tags = var.tags
}
