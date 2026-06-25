"""Cognito post-confirmation trigger.

Fires once per user when they confirm their account. Calls subscription-service
``POST /internal/provision/signup`` to atomically create platform tenant, org,
and OWNER membership (TENANT_ORG_MODEL).

Never blocks sign-up on provisioning failure — log and continue.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from subscription_client import provision_signup

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)


def _display_name_from_event(event: dict[str, Any]) -> str | None:
    attrs = event.get("request", {}).get("userAttributes", {})
    email = attrs.get("email") or attrs.get("cognito:email")
    if isinstance(email, str) and "@" in email:
        local = email.split("@", 1)[0].strip()
        if local:
            return local
    name = attrs.get("name") or attrs.get("given_name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return None


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    trigger = event.get("triggerSource", "")
    if trigger != "PostConfirmation_ConfirmSignUp":
        logger.info("skipping triggerSource=%s", trigger)
        return event

    user_id: str = event.get("request", {}).get("userAttributes", {}).get("sub", "")
    if not user_id:
        logger.error("missing sub in userAttributes; event=%s", event)
        return event

    logger.info("post_confirmation trigger=%s user_id=%s", trigger, user_id)

    try:
        result = provision_signup(user_id, _display_name_from_event(event))
        if result:
            logger.info(
                "provisioned signup user_id=%s tenant_id=%s org_id=%s",
                user_id,
                result.get("tenantId"),
                result.get("orgId"),
            )
        else:
            logger.error("provision signup returned no result for user_id=%s", user_id)
    except Exception:
        logger.exception("failed to provision signup for user_id=%s", user_id)

    return event
