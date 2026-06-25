"""Cognito pre-token-generation trigger (V2).

Queries org memberships and injects TENANT_ORG_MODEL claims:
  tenant_id, org_id, org_memberships[{tenant_id, org_id, role}]

Backfills missing tenant_id via subscription-service GET /internal/orgs/{orgId}/config.
Auto-provisions federated users via POST /internal/provision/signup when empty.
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


def _fetch_memberships(user_id: str) -> list[dict[str, str]]:
    memberships: list[dict[str, str]] = []
    resp = _table.query(
        KeyConditionExpression=Key("PK").eq(user_id),
        ProjectionExpression="SK, #r, tenant_id",
        ExpressionAttributeNames={"#r": "role"},
        Limit=MAX_MEMBERSHIPS_IN_CLAIMS + 1,
    )
    for item in resp.get("Items", []):
        org_id = str(item["SK"])
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
            "user %s has %d memberships; truncating to %d",
            user_id,
            len(memberships),
            MAX_MEMBERSHIPS_IN_CLAIMS,
        )
        memberships = memberships[:MAX_MEMBERSHIPS_IN_CLAIMS]
    return memberships


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


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    trigger = event.get("triggerSource", "")
    user_id = event["request"]["userAttributes"].get("sub")

    logger.info("pre_token_generation trigger=%s user_id=%s", trigger, user_id)

    if not user_id:
        logger.error("missing sub claim in request; returning event unchanged")
        return event

    try:
        memberships = _fetch_memberships(user_id)
    except Exception:
        logger.exception("failed to fetch memberships for user_id=%s", user_id)
        memberships = []

    if not memberships:
        try:
            provisioned = _provision_via_api(user_id)
            if provisioned:
                memberships = [provisioned]
        except Exception:
            logger.exception("failed to auto-provision user_id=%s", user_id)

    primary = memberships[0] if memberships else {}
    primary_org_id = primary.get("org_id")
    primary_tenant_id = primary.get("tenant_id")

    logger.info(
        "injecting membership claims user_id=%s tenant_id=%s org_id=%s count=%d",
        user_id,
        primary_tenant_id,
        primary_org_id,
        len(memberships),
    )

    id_claims: dict[str, Any] = {"org_memberships": memberships}
    access_claims: dict[str, Any] = {}

    if primary_org_id:
        id_claims["org_id"] = primary_org_id
        access_claims["org_id"] = primary_org_id
        id_claims["primary_org_id"] = primary_org_id
        access_claims["primary_org_id"] = primary_org_id

    if primary_tenant_id:
        id_claims["tenant_id"] = primary_tenant_id
        access_claims["tenant_id"] = primary_tenant_id

    if memberships:
        access_claims["org_memberships"] = json.dumps(memberships)

    event["response"] = {
        "claimsAndScopeOverrideDetails": {
            "idTokenGeneration": {"claimsToAddOrOverride": id_claims},
            "accessTokenGeneration": {"claimsToAddOrOverride": access_claims},
        }
    }
    return event
