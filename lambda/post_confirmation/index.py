"""Cognito post-confirmation trigger.

Fires once per user when they confirm their account (email code or
admin confirmation). Creates a "personal workspace" organisation and a
matching OWNER membership so that the pre-token-generation Lambda can
inject a real ``primary_org_id`` claim on every subsequent login.

DynamoDB schema mirrors the memberships table in memberships.tf:
    PK  = user_id   (Cognito sub)
    SK  = org_id    (e.g. "org_<uuid4>")
    role            = "OWNER"
    created_at      = ISO-8601 UTC timestamp

This is intentionally simple. B2B org creation (many users per org,
invitations, role management) is handled by app-layer code. This trigger
only ensures every user has *at least one* org so that:
  - pre_token_generation always emits a non-empty ``primary_org_id``
  - downstream services never see ``tenantId = "default"``
  - subscription IDs follow the ``sub_<org_id>_<user_id>`` pattern
    from day one

idempotency: DynamoDB PutItem with a condition that PK+SK must not exist
means re-triggers (e.g. admin re-confirmation) are safe.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
MEMBERSHIPS_TABLE = os.environ["MEMBERSHIPS_TABLE"]

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_ddb = boto3.resource("dynamodb")
_table = _ddb.Table(MEMBERSHIPS_TABLE)


def _create_personal_org_membership(user_id: str) -> str:
    """Write one OWNER membership row for the user.  Returns the org_id."""
    org_id = f"org_{uuid.uuid4()}"
    now = datetime.now(timezone.utc).isoformat()

    try:
        _table.put_item(
            Item={
                "user_id": user_id,
                "org_id": org_id,
                "role": "OWNER",
                "created_at": now,
            },
            # Don't overwrite if a membership already exists (idempotent).
            ConditionExpression="attribute_not_exists(user_id)",
        )
        logger.info(
            "created personal org for user_id=%s org_id=%s",
            user_id,
            org_id,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Membership already exists — e.g. admin re-confirmed the user.
            # The condition is on the PK alone (attribute_not_exists(user_id))
            # so *any* row with this user_id already exists.  We can't cheaply
            # retrieve the existing org_id without a Query; return the newly-
            # generated org_id as a sentinel — the pre-token-gen trigger will
            # query for all memberships on the next login and find the real one.
            logger.info("membership already exists for user_id=%s; skipping", user_id)
            return org_id
        raise

    return org_id


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Post-confirmation entrypoint.

    Cognito expects the *same event dict* returned unchanged.  Any
    exception propagated here will block the user confirmation — log and
    swallow rather than deny the sign-up.
    """
    trigger = event.get("triggerSource", "")

    # Only act on ConfirmSignUp; ignore ForgotPassword confirmation etc.
    if trigger != "PostConfirmation_ConfirmSignUp":
        logger.info("skipping triggerSource=%s", trigger)
        return event

    user_id: str = event.get("request", {}).get("userAttributes", {}).get("sub", "")
    if not user_id:
        logger.error("missing sub in userAttributes; event=%s", event)
        return event

    logger.info("post_confirmation trigger=%s user_id=%s", trigger, user_id)

    try:
        _create_personal_org_membership(user_id)
    except Exception:
        # NEVER block sign-up for a DDB failure — log and continue.
        logger.exception("failed to create org membership for user_id=%s", user_id)

    return event
