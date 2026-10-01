"""Cognito post-confirmation trigger.

Fires once per user when they confirm their account. Calls subscription-service
``POST /internal/provision/signup`` to atomically create platform tenant, org,
and OWNER membership (TENANT_ORG_MODEL).

Never blocks sign-up on provisioning failure — log and continue.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from subscription_client import provision_signup

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

_ENTERPRISE_SSO_PROVIDER = re.compile(r"^sso[a-f0-9]{29}$")
_ENTERPRISE_SSO_USERNAME = re.compile(r"^sso[a-f0-9]{29}_")


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


def _parse_identities(user_attributes: dict[str, Any]) -> list[dict[str, Any]]:
    raw = user_attributes.get("identities")
    if not raw:
        return []
    try:
        identities = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(identities, list):
        return []
    return [i for i in identities if isinstance(i, dict)]


def _is_enterprise_sso_user(event: dict[str, Any], user_attributes: dict[str, Any]) -> bool:
    """True when this Cognito profile is an enterprise Tenant IdP destination.

    Match PreToken: username ``sso{29hex}_…``, bare provider name, or a
    **primary** identity whose provider is ``sso{29hex}``. Hosted UI can pass
    the UUID ``sub`` as ``userName`` — must not JIT a personal org in that case.
    """
    for candidate in (
        str(event.get("userName") or ""),
        str(user_attributes.get("cognito:username") or ""),
    ):
        if _ENTERPRISE_SSO_USERNAME.match(candidate):
            return True
        if _ENTERPRISE_SSO_PROVIDER.match(candidate):
            return True
    for identity in _parse_identities(user_attributes):
        primary = identity.get("primary")
        is_primary = primary is True or str(primary).lower() in {"true", "1", "yes"}
        if not is_primary:
            continue
        name = str(identity.get("providerName") or "")
        if _ENTERPRISE_SSO_PROVIDER.match(name):
            return True
    return False


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    trigger = event.get("triggerSource", "")
    if trigger != "PostConfirmation_ConfirmSignUp":
        logger.info("skipping triggerSource=%s", trigger)
        return event

    user_attributes = event.get("request", {}).get("userAttributes", {}) or {}
    user_id: str = user_attributes.get("sub", "")
    if not user_id:
        logger.error("missing sub in userAttributes; event=%s", event)
        return event

    logger.info("post_confirmation trigger=%s user_id=%s", trigger, user_id)

    # Enterprise SSO destinations must not get a personal Tenant — PreToken
    # adopts memberships from the email peer (Google_*/native). JIT here races
    # adopt and sends users to choose-a-plan with an empty wallet.
    if _is_enterprise_sso_user(event, user_attributes):
        logger.info(
            "skipping personal-org provision for enterprise SSO user_id=%s",
            user_id,
        )
        return event

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
