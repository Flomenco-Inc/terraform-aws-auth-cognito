#!/usr/bin/env python3
"""Ensure every runtime Tenant IdP (sso + 29 hex) is on the SPA app client.

Terraform manages the SPA client baseline (COGNITO + Google) and uses
lifecycle.ignore_changes on supported_identity_providers so applies do not
wipe runtime IdPs. This script is the heal/assert path — run from the auth
leaf GHA step (post-apply) or identity-service after IdP upsert. Do not
invoke via Terraform local-exec (apply containers may lack python3).

Env:
  COGNITO_USER_POOL_ID
  COGNITO_USER_POOL_CLIENT_ID
"""

from __future__ import annotations

import os
import re
import sys

import boto3
from botocore.exceptions import ClientError

ENTERPRISE = re.compile(r"^sso[a-f0-9]{29}$")


def _required(name: str) -> str:
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise SystemExit(f"missing required env {name}")
    return value


def list_enterprise_providers(cognito, pool_id: str) -> list[str]:
    names: list[str] = []
    token: str | None = None
    while True:
        kwargs: dict = {"UserPoolId": pool_id, "MaxResults": 60}
        if token:
            kwargs["NextToken"] = token
        page = cognito.list_identity_providers(**kwargs)
        for provider in page.get("Providers") or []:
            name = provider.get("ProviderName") or ""
            if ENTERPRISE.match(name):
                names.append(name)
        token = page.get("NextToken")
        if not token:
            break
    return sorted(set(names))


def describe_client(cognito, pool_id: str, client_id: str) -> dict:
    return cognito.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=client_id
    )["UserPoolClient"]


def update_supported(cognito, existing: dict, providers: list[str]) -> None:
    # Preserve every mutable field Cognito resets when omitted.
    keep = [
        "ClientName",
        "RefreshTokenValidity",
        "AccessTokenValidity",
        "IdTokenValidity",
        "TokenValidityUnits",
        "ReadAttributes",
        "WriteAttributes",
        "ExplicitAuthFlows",
        "CallbackURLs",
        "LogoutURLs",
        "DefaultRedirectURI",
        "AllowedOAuthFlows",
        "AllowedOAuthScopes",
        "AllowedOAuthFlowsUserPoolClient",
        "PreventUserExistenceErrors",
        "EnableTokenRevocation",
        "EnablePropagateAdditionalUserContextData",
        "AuthSessionValidity",
        "AnalyticsConfiguration",
    ]
    body: dict = {
        "UserPoolId": existing["UserPoolId"],
        "ClientId": existing["ClientId"],
        "SupportedIdentityProviders": providers,
    }
    for key in keep:
        if key in existing:
            body[key] = existing[key]
    cognito.update_user_pool_client(**body)


def main() -> int:
    pool_id = _required("COGNITO_USER_POOL_ID")
    client_id = _required("COGNITO_USER_POOL_CLIENT_ID")
    cognito = boto3.client("cognito-idp")

    try:
        enterprise = list_enterprise_providers(cognito, pool_id)
        existing = describe_client(cognito, pool_id, client_id)
    except ClientError as err:
        print(f"ERROR: describe/list failed: {err}", file=sys.stderr)
        return 1

    current = list(existing.get("SupportedIdentityProviders") or [])
    current_set = set(current)
    missing = [name for name in enterprise if name not in current_set]

    print(f"pool={pool_id} client={client_id}")
    print(f"enterprise_idps={len(enterprise)} spa_providers={current}")
    if not missing:
        print("OK: SPA client already includes every enterprise IdP")
        return 0

    print(f"HEAL: attaching missing IdPs: {missing}")
    healed = list(dict.fromkeys([*current, *missing]))
    try:
        update_supported(cognito, existing, healed)
        after = describe_client(cognito, pool_id, client_id)
    except ClientError as err:
        print(f"ERROR: update failed: {err}", file=sys.stderr)
        return 1

    after_set = set(after.get("SupportedIdentityProviders") or [])
    still_missing = [name for name in enterprise if name not in after_set]
    if still_missing:
        print(f"ERROR: still missing after heal: {still_missing}", file=sys.stderr)
        return 1

    print(f"OK: healed SPA providers -> {sorted(after_set)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
