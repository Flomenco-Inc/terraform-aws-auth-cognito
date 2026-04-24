"""Cognito pre-token-generation trigger (V2).

On every token mint (login + refresh), query DynamoDB for the user's
org memberships and inject them into the ID + access token claims.

Shape of the injected claims (at JWT root, not namespaced):
    org_memberships: list[{"org_id": str, "role": str}]
    primary_org_id:  str | None

Runtime: python3.12. No external dependencies — boto3 + stdlib only so
the deployment zip stays tiny (~3KB) and cold starts stay fast (~400ms).

Cognito fails the login if this trigger exceeds 5s end-to-end. Keep the
DDB query single-partition (PK = user_id) — a user with hundreds of
memberships is a red flag worth surfacing rather than silently bloating
the JWT.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
MEMBERSHIPS_TABLE = os.environ["MEMBERSHIPS_TABLE"]

# JWTs have a practical size ceiling (~8KB before browsers start rejecting
# cookies / headers). A user in 50 orgs at ~80 bytes per entry is already
# 4KB of claims alone; truncate defensively and log a warning so we can
# investigate rather than silently break auth.
MAX_MEMBERSHIPS_IN_CLAIMS = 50

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

# Module-level client reuse across warm invocations.
_ddb = boto3.resource("dynamodb")
_table = _ddb.Table(MEMBERSHIPS_TABLE)


def _fetch_memberships(user_id: str) -> list[dict[str, str]]:
    """Query the memberships table for the given user. Returns a list of
    {org_id, role} dicts ordered as DynamoDB returns them (sort key asc).
    """
    memberships: list[dict[str, str]] = []
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ProjectionExpression": "org_id, #r",
        "ExpressionAttributeNames": {"#r": "role"},
        "Limit": MAX_MEMBERSHIPS_IN_CLAIMS + 1,
    }

    resp = _table.query(**kwargs)
    for item in resp.get("Items", []):
        memberships.append(
            {
                "org_id": str(item["org_id"]),
                "role": str(item["role"]),
            }
        )

    if len(memberships) > MAX_MEMBERSHIPS_IN_CLAIMS:
        logger.warning(
            "user %s has %d memberships; truncating to %d in claims",
            user_id,
            len(memberships),
            MAX_MEMBERSHIPS_IN_CLAIMS,
        )
        memberships = memberships[:MAX_MEMBERSHIPS_IN_CLAIMS]

    return memberships


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Pre-token-generation V2 entrypoint.

    We do NOT raise on DDB errors — a failed membership lookup should NOT
    deny the user a token. Better to log in with empty memberships and
    let the app surface a "no orgs found" state than to fail auth entirely.
    """
    trigger = event.get("triggerSource", "")
    user_id = event["request"]["userAttributes"].get("sub")

    logger.info(
        "pre_token_generation trigger=%s user_id=%s",
        trigger,
        user_id,
    )

    if not user_id:
        logger.error("missing sub claim in request; returning event unchanged")
        return event

    try:
        memberships = _fetch_memberships(user_id)
    except Exception:
        # Log full traceback to CloudWatch but don't fail auth.
        logger.exception("failed to fetch memberships for user_id=%s", user_id)
        memberships = []

    primary_org_id = memberships[0]["org_id"] if memberships else None

    claims_to_add: dict[str, Any] = {
        "org_memberships": memberships,
    }
    if primary_org_id is not None:
        claims_to_add["primary_org_id"] = primary_org_id

    # V2 shape: per-token-type claim overrides. We write to both id token
    # and access token so API Gateway JWT authorizers (which validate the
    # access token) see the same memberships as the SPA (which reads the
    # ID token).
    event["response"] = {
        "claimsAndScopeOverrideDetails": {
            "idTokenGeneration": {
                "claimsToAddOrOverride": claims_to_add,
            },
            "accessTokenGeneration": {
                "claimsToAddOrOverride": claims_to_add,
            },
        }
    }

    logger.debug("response=%s", json.dumps(event["response"]))
    return event
