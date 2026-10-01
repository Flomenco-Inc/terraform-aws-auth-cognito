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

## Related

- flo session: `docs/session-notes/2026-10-01-sso-enforce-okta-adopt-choose-plan.md`
- flo-core-services: `.cursor/rules/auth-leaf-spa-idp-reconcile.mdc`
