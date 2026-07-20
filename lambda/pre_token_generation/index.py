"""Cognito pre-token-generation trigger (V2).

Queries org memberships and injects TENANT_ORG_MODEL claims:
  tenant_id, org_id (active org), org_memberships[{tenant_id, org_id, role}],
  teams, permissions (org-scoped resolved union, when available)

Active-org binding: the session is bound to one org. `POST /me/active-org`
(me-service) persists an ACTIVE_ORG row in this table; every token mint reads
it and re-mints all org-scoped claims for that org. Fallback when no selection
exists: sole membership, then first membership (primary).

Table layout (PK = Cognito sub):
  SK = "org_<uuid>"                       membership row {role, tenant_id}
  SK = "ACTIVE_ORG"                       active-org selection {org_id}
  SK = "RESOLVED_PERMISSIONS#<org_id>"    resolved grants {permissions, teams}
                                          (written by identity-service workers)

Fail-closed: if the membership lookup errors, the trigger raises and Cognito
denies the token — an unscoped token must never be minted. "No rows" is not an
error: it routes to auto-provision (Flo self-serve bootstrap deviation from
mlv2 FR-4).

Backfills missing tenant_id via subscription-service GET /internal/orgs/{orgId}/config.
Auto-provisions federated users via POST /internal/provision/signup when empty.

Claim size guardrail: access-token claims are budgeted; on overflow the
permissions payload is dropped and `permissions_overflow` is set so the
authorizer falls back to reading RESOLVED_PERMISSIONS from DynamoDB.

Email on access tokens: Cognito puts `email` / `email_verified` on ID tokens
by default but not on access tokens. The Flo SPA sends access tokens to the
API (`getAccessToken()`), so JWT_ONLY routes that match invitee email
(e.g. accept-invitation) must see those claims on the access token too.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

from subscription_client import get_org_config, provision_signup

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
MEMBERSHIPS_TABLE = os.environ["MEMBERSHIPS_TABLE"]
MAX_MEMBERSHIPS_IN_CLAIMS = 50

ACTIVE_ORG_SK = "ACTIVE_ORG"
RESOLVED_PERMISSIONS_SK_PREFIX = "RESOLVED_PERMISSIONS#"

# JWTs have a practical size ceiling (~8KB before proxies/browsers reject the
# Authorization header). Budget the claims we inject and shed the permissions
# payload first when over budget.
ACCESS_CLAIMS_BYTE_BUDGET = int(os.environ.get("ACCESS_CLAIMS_BYTE_BUDGET", "6144"))

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_ddb = boto3.resource("dynamodb")
_table = _ddb.Table(MEMBERSHIPS_TABLE)
_org_config_cache: dict[str, dict[str, str]] = {}


def _resolve_tenant_id(org_id: str, item_tenant_id: str | None) -> str | None:
    if item_tenant_id:
        return str(item_tenant_id)
    cached = _org_config_cache.get(org_id)
    if cached and cached.get("tenantId"):
        return cached["tenantId"]
    config = get_org_config(org_id)
    if config and config.get("tenantId"):
        _org_config_cache[org_id] = {
            "tenantId": str(config["tenantId"]),
            "orgId": str(config.get("orgId", org_id)),
        }
        return str(config["tenantId"])
    return None


def _fetch_user_rows(user_id: str) -> list[dict[str, Any]]:
    """Single-partition read of all identity rows for the user."""
    resp = _table.query(
        KeyConditionExpression=Key("PK").eq(user_id),
    )
    return list(resp.get("Items", []))


def _memberships_from_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    memberships: list[dict[str, str]] = []
    for item in rows:
        sk = str(item.get("SK", ""))
        # Non-membership rows share the partition — never treat them as orgs.
        if sk == ACTIVE_ORG_SK or sk.startswith(RESOLVED_PERMISSIONS_SK_PREFIX):
            continue
        if "role" not in item:
            logger.warning("membership row missing role; skipping SK=%s", sk)
            continue
        org_id = sk
        tenant_id = _resolve_tenant_id(org_id, item.get("tenant_id"))
        entry: dict[str, str] = {
            "org_id": org_id,
            "role": str(item["role"]),
        }
        if tenant_id:
            entry["tenant_id"] = tenant_id
        memberships.append(entry)

    if len(memberships) > MAX_MEMBERSHIPS_IN_CLAIMS:
        logger.warning(
            "truncating %d memberships to %d in claims",
            len(memberships),
            MAX_MEMBERSHIPS_IN_CLAIMS,
        )
        memberships = memberships[:MAX_MEMBERSHIPS_IN_CLAIMS]
    return memberships


def _active_org_from_rows(rows: list[dict[str, Any]]) -> str | None:
    for item in rows:
        if str(item.get("SK", "")) == ACTIVE_ORG_SK:
            org_id = item.get("org_id")
            if isinstance(org_id, str) and org_id:
                return org_id
    return None


def _resolved_grants_from_rows(
    rows: list[dict[str, Any]], org_id: str
) -> tuple[list[str], list[str]]:
    """Return (permissions, teams) for the active org, empty when unresolved."""
    target_sk = f"{RESOLVED_PERMISSIONS_SK_PREFIX}{org_id}"
    for item in rows:
        if str(item.get("SK", "")) != target_sk:
            continue
        permissions_raw = item.get("permissions")
        teams_raw = item.get("teams")
        permissions = [str(p) for p in permissions_raw] if isinstance(permissions_raw, list) else []
        teams = [str(t) for t in teams_raw] if isinstance(teams_raw, list) else []
        return permissions, teams
    return [], []


def _provision_via_api(user_id: str) -> dict[str, str] | None:
    result = provision_signup(user_id)
    if not result:
        return None
    tenant_id = str(result.get("tenantId", ""))
    org_id = str(result.get("orgId", ""))
    if not tenant_id or not org_id:
        return None
    return {
        "tenant_id": tenant_id,
        "org_id": org_id,
        "role": str(result.get("membershipRole", "OWNER")),
    }


def _email_claims_from_user_attributes(
    user_attributes: dict[str, Any],
) -> dict[str, str]:
    """Copy Cognito standard email attrs onto access-token claim overrides.

    ID tokens already carry these from Cognito; access tokens do not unless we
    add them here. Values are always strings (API Gateway / Cognito claim map).
    """
    claims: dict[str, str] = {}
    email = user_attributes.get("email")
    if isinstance(email, str) and email.strip():
        claims["email"] = email.strip()

    raw_verified = user_attributes.get("email_verified")
    if raw_verified is True or (
        isinstance(raw_verified, str) and raw_verified.strip().lower() in {"true", "1", "yes"}
    ):
        claims["email_verified"] = "true"
    elif raw_verified is False or (
        isinstance(raw_verified, str) and raw_verified.strip().lower() in {"false", "0", "no"}
    ):
        claims["email_verified"] = "false"
    return claims


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    trigger = event.get("triggerSource", "")
    user_attributes = event["request"]["userAttributes"]
    user_id = user_attributes.get("sub")

    logger.info("pre_token_generation trigger=%s user_id=%s", trigger, user_id)

    if not user_id:
        # Fail-closed: a token without a subject must not be enriched or minted.
        raise RuntimeError("pre_token_generation: missing sub in userAttributes")

    # Fail-closed: a lookup failure raises and denies the token. Minting a
    # token with silently-empty memberships would either scope the user to
    # nothing or trigger a spurious re-provision.
    rows = _fetch_user_rows(user_id)
    memberships = _memberships_from_rows(rows)

    if not memberships:
        # No rows is a legitimate first-login state (federated signup) —
        # auto-provision inline (Flo self-serve deviation from mlv2 FR-4).
        provisioned = _provision_via_api(user_id)
        if not provisioned:
            # Fail-closed: an org-less token must never be minted. Denying the
            # login is recoverable (retry); an unscoped session is not.
            raise RuntimeError(
                f"pre_token_generation: no memberships and provisioning failed "
                f"for user {user_id}"
            )
        memberships = [provisioned]

    # Active-org resolution: explicit ACTIVE_ORG selection (validated against
    # memberships — fail-safe if the user was since removed), else sole/primary.
    selected_org_id = _active_org_from_rows(rows)
    active = None
    if selected_org_id:
        active = next(
            (m for m in memberships if m["org_id"] == selected_org_id), None
        )
        if active is None:
            logger.warning(
                "ACTIVE_ORG %s is not among user %s memberships; falling back",
                selected_org_id,
                user_id,
            )
    if active is None and memberships:
        active = memberships[0]

    org_id = active.get("org_id") if active else None
    tenant_id = active.get("tenant_id") if active else None

    permissions: list[str] = []
    teams: list[str] = []
    if org_id:
        permissions, teams = _resolved_grants_from_rows(rows, org_id)

    logger.info(
        "injecting claims user_id=%s tenant_id=%s org_id=%s memberships=%d "
        "permissions=%d teams=%d",
        user_id,
        tenant_id,
        org_id,
        len(memberships),
        len(permissions),
        len(teams),
    )

    id_claims: dict[str, Any] = {"org_memberships": memberships}
    access_claims: dict[str, Any] = {}

    # Access tokens lack Cognito's standard email claims unless overridden.
    access_claims.update(_email_claims_from_user_attributes(user_attributes))

    if org_id:
        id_claims["org_id"] = org_id
        access_claims["org_id"] = org_id
        # primary_org_id kept for backward compatibility with consumers that
        # predate the active-org claim; it now mirrors the active org.
        id_claims["primary_org_id"] = org_id
        access_claims["primary_org_id"] = org_id

    if tenant_id:
        id_claims["tenant_id"] = tenant_id
        access_claims["tenant_id"] = tenant_id

    if memberships:
        access_claims["org_memberships"] = json.dumps(memberships)

    if teams:
        id_claims["teams"] = teams
        access_claims["teams"] = json.dumps(teams)

    if permissions:
        id_claims["permissions"] = permissions
        access_claims["permissions"] = json.dumps(permissions)

    # Size guardrail: shed the permissions payload first; the authorizer falls
    # back to reading RESOLVED_PERMISSIONS from DynamoDB when the marker is set.
    claims_size = len(json.dumps(access_claims).encode("utf-8"))
    if claims_size > ACCESS_CLAIMS_BYTE_BUDGET and "permissions" in access_claims:
        logger.warning(
            "access claims %dB exceed budget %dB; dropping permissions claim",
            claims_size,
            ACCESS_CLAIMS_BYTE_BUDGET,
        )
        del access_claims["permissions"]
        id_claims.pop("permissions", None)
        access_claims["permissions_overflow"] = "true"
        id_claims["permissions_overflow"] = "true"
        claims_size = len(json.dumps(access_claims).encode("utf-8"))

    if claims_size > ACCESS_CLAIMS_BYTE_BUDGET:
        # org_memberships/teams alone exceed the budget — signal loudly; the
        # memberships cap (MAX_MEMBERSHIPS_IN_CLAIMS) should make this rare.
        logger.warning(
            "access claims %dB still exceed budget %dB after shedding permissions",
            claims_size,
            ACCESS_CLAIMS_BYTE_BUDGET,
        )

    event["response"] = {
        "claimsAndScopeOverrideDetails": {
            "idTokenGeneration": {"claimsToAddOrOverride": id_claims},
            "accessTokenGeneration": {"claimsToAddOrOverride": access_claims},
        }
    }
    return event
