# terraform-aws-auth-cognito

Cognito user pool sized for a B2B product: one pool, many orgs, rich JWT
claims hydrated from DynamoDB on every token mint.

**Why this exists**: vanilla Cognito has no "organization" concept — users
are flat. This module layers a canonical org-memberships model on top
using a DynamoDB table + a pre-token-generation V2 Lambda, so every
JWT carries the caller's full `{ org_id, role }` set at the root of the
token. API Gateway authorizers and [AVP / Cedar][avp] consume the claim
directly, no namespace parsing.

## What it creates

- `aws_cognito_user_pool` — email sign-in, verified email required,
  12-char password minimum, MFA-off by default (flip to OPTIONAL later
  without breaking anyone)
- `aws_cognito_user_pool_client` — SPA (authorization code + PKCE, no
  client secret, token revocation enabled)
- `aws_cognito_user_pool_domain` — default Cognito domain, OR a custom
  domain if `custom_domain` + `custom_domain_certificate_arn` are set
- `aws_cognito_identity_provider` for Google — conditional on
  `enable_google`
- `aws_dynamodb_table` `<name>-org-memberships` — PK `user_id`, SK
  `org_id`, GSI1 `org_id`/`user_id` for reverse lookups
- `aws_lambda_function` pre-token-generation (Python 3.12, V2 trigger)
  with CloudWatch log group + least-privilege IAM

## Usage (Terragrunt)

```hcl
include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  base   = read_terragrunt_config(find_in_parent_folders("_base/auth.hcl"))
  env    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region = read_terragrunt_config(find_in_parent_folders("region.hcl"))
}

terraform {
  source = "${local.base.locals.source_auth_url}//?ref=${local.base.locals.source_auth_ref}"
}

inputs = {
  name          = "flo-${local.env.locals.env_name}"
  domain_prefix = "flo-${local.env.locals.env_name}"

  callback_urls = ["https://app.dev.flomenco.com/auth/callback", "http://localhost:5173/auth/callback"]
  logout_urls   = ["https://app.dev.flomenco.com/", "http://localhost:5173/"]

  # Day one: pool up, Google off. Flip to true once the Google OAuth
  # client is registered with the Cognito idpresponse URL and the
  # credentials are in Secrets Manager.
  enable_google = false

  deletion_protection                = "INACTIVE" # dev only
  memberships_point_in_time_recovery = false      # dev only
}
```

## Sequencing: enabling Google after first apply

Google OAuth clients need the Cognito domain to exist before you can
register their redirect URI. Apply twice:

1. **First apply** — `enable_google = false`. This creates the user pool
   and its hosted UI domain.
2. **Register with Google**:
   - Google Cloud Console → APIs & Services → Credentials → Create OAuth
     2.0 Client ID (Web Application).
   - Authorized redirect URI:
     `https://<domain_prefix>.auth.<region>.amazoncognito.com/oauth2/idpresponse`
     (or `https://<custom_domain>/oauth2/idpresponse` if using a custom
     domain).
   - Copy the client ID + client secret.
3. **Store credentials** in AWS Secrets Manager (recommend
   `<name>/google-oauth-client` with JSON `{ "client_id": ..., "client_secret": ... }`).
4. **Second apply** — `enable_google = true`, with `google_client_id` /
   `google_client_secret` wired from the secret (Terragrunt's
   `local.secrets` via `aws_secretsmanager_secret_version` data source or
   a `sops_decrypt_file` pattern).

## Consuming the claims

The pre-token-generation Lambda emits these claims at the root of both
the ID token and the access token:

```json
{
  "org_memberships": [
    { "org_id": "flo",  "role": "owner" },
    { "org_id": "acme", "role": "member" }
  ],
  "primary_org_id": "flo"
}
```

`primary_org_id` is a UX hint (the app can default routing here on
login) — `org_memberships` is the authoritative list. AVP / Cedar
policies reference it as `principal.org_memberships[...]`.

**Active-org handling is out of scope** for this module. Standard pattern:
client sends an `X-Org-Id` header per API call; the API Gateway authorizer
or Lambda combines the JWT memberships list with the header to compute
the current-acting role for the request, then evaluates Cedar policies
against that.

## Outputs you'll wire elsewhere

| Output | Consumer |
|---|---|
| `oidc_issuer` | AVP `oidc_issuer`, API Gateway JWT authorizer, any Lambda validator |
| `oidc_audience` | AVP `oidc_audiences` (wrap in `[]`) |
| `spa_client_id` | Frontend env var `VITE_COGNITO_CLIENT_ID` |
| `hosted_ui_domain` | Frontend env var `VITE_COGNITO_DOMAIN` |
| `oauth_authorize_url` / `oauth_token_url` / `oauth_logout_url` | Frontend OIDC client config |
| `memberships_table_name` | Backend service that writes memberships (org creation, invite accept, role change) |

## Caller-owned provider

This module deliberately does **not** declare a `provider "aws"` block.
The caller (Terragrunt root.hcl, typically) owns `region`,
`default_tags`, `allowed_account_ids`, and `assume_role`. If you see a
`Duplicate provider configuration` error on consume, check your caller
isn't also declaring one from a stale reference.

[avp]: https://github.com/Flomenco-Inc/terraform-aws-avp
