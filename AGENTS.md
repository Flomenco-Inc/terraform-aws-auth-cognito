# AI Agent Context — `terraform-aws-auth-cognito`

Shared Cognito user pool + org-memberships DynamoDB + PreToken / PostConfirmation
Lambdas for Flo (`flo-<env>` pools).

## Tenant SSO (runtime IdPs)

Product / SPA rules live in **flo** `.cursor/rules/tenant-sso-okta.mdc` and
flo-docs ADR `docs/adr/0002-runtime-cognito-tenant-idps.md`.

This module must:

1. Keep SPA baseline IdPs (`COGNITO` + Google) in Terraform.
2. Use `lifecycle.ignore_changes = [supported_identity_providers]` on the SPA
   client so auth applies do not wipe runtime `sso*` IdPs.
3. Ship `scripts/reconcile_spa_identity_providers.py` as the heal/assert tool.
   Callers: flo-core-services **apply auth leaf** (GHA) and flo identity-service
   on IdP upsert. **Do not** wire heal via Terraform `local-exec` (dagger apply
   images lack `python3`).

## First enterprise login (PreToken / PostConfirmation)

Google-first users get a distinct Cognito `sso_*` user on first Okta login.

| Lambda | Must |
|--------|------|
| PostConfirmation | Skip personal-org JIT when username is `sso{29hex}_…` **or** primary identity provider is `sso{29hex}` (Hosted UI may pass UUID `userName`). |
| PreToken | Always **merge** memberships from verified-email peers for enterprise users — do **not** gate adopt on empty memberships. Okta often has `email_verified=false`. |

Unit tests: `lambda/pre_token_generation/test_index.py`,
`lambda/post_confirmation/test_index.py`.

After hot-patching Lambdas in an env, run flo-core-services **apply auth leaf**
so Terragrunt owns the deployed zip again.

## Platform admins group (flo#2554)

`platform_admins.tf` creates `flo-platform-admins` in every pool. The Flo
custom authorizer maps that `cognito:groups` value to the platform-plane
capabilities (`PLATFORM_ADMIN_GROUP_CAPABILITIES`); nothing else grants them.

| Rule | Why |
|------|-----|
| Membership is only `var.platform_admin_usernames` (set per env leaf in flo-core-services) | A reviewed PR is the audit trail; console or CLI membership is drift nobody approved |
| Do not rename the group | The authorizer matches the exact name |
| Do not add `groupOverrideDetails` to PreToken | It would let Lambda code rewrite `cognito:groups`, the only source of platform grants |
| Never grant `cognito-idp:AdminAddUserToGroup` to CI or app roles | Same reason; only the Terraform apply role adds members |

Plan-only tests: `terraform init -backend=false && terraform test`
(`tests/platform_admins.tftest.hcl`). Runbook: flo `docs/platform-admins.md`.

## SPA client attribute permissions (flo#2571)

`aws_cognito_user_pool_client.spa` sets an explicit `write_attributes`
(`local.spa_write_attributes`). Unset means users can self-write every
attribute with `UpdateUserAttributes`, including `custom:role` /
`custom:primary_org_id`.

| Rule | Why |
|------|-----|
| Never list a `custom:*` attribute | Users would self-assign it; a precondition and `tests/spa_client_attributes.tftest.hcl` fail the plan |
| Keep every IdP-mapped attribute (Google, identity-service `FIXED_ATTRIBUTE_MAPPING`) in the list | Cognito skips a mapped attribute the client can't write |
| Never list `email_verified` | Cognito rejects it (`Invalid write attributes specified`) |
| Leave `read_attributes` at the default | The SPA reads `custom:role` from the ID token for display |

The identity-service and flo-core-services SPA IdP reconcilers copy
`WriteAttributes` from `DescribeUserPoolClient`, so they keep this list.

## Related

- flo session: `docs/session-notes/2026-10-01-sso-enforce-okta-adopt-choose-plan.md`
- flo-core-services: `.cursor/rules/auth-leaf-spa-idp-reconcile.mdc`
