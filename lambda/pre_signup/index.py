"""Pre-signup trigger — federated account linking.

When a user with an existing native Cognito account (created by AdminCreateUser
during an org invite) authenticates via Google OAuth for the first time, Cognito
would ordinarily create a *second* identity with a different sub. That breaks org
membership lookup: the memberships table row was written for the native sub, not
the Google sub.

This trigger fires *before* the federated user is created. When the incoming
email matches an existing native user it calls AdminLinkProviderForUser so that
all subsequent Google logins are routed to the native identity (same sub, same
memberships row).

Trigger source: PreSignUp_ExternalProvider (Google, Facebook, etc.)
All other trigger sources are passed through unchanged.

Safety contract: never raises an exception that would block sign-up. Linking
failures are logged and the sign-up proceeds as normal (graceful degradation:
the user gets a new federated identity without the org membership — still better
than blocking them entirely).
"""

import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

USER_POOL_ID: str = os.environ["USER_POOL_ID"]

_cognito: Any = None


def _client() -> Any:
    global _cognito
    if _cognito is None:
        _cognito = boto3.client("cognito-idp")
    return _cognito


def _find_native_user(email: str) -> dict[str, Any] | None:
    """Return the first native (non-federated) Cognito user with this email, or None."""
    result = _client().list_users(
        UserPoolId=USER_POOL_ID,
        Filter=f'email = "{email}"',
        Limit=10,
    )
    federated_prefixes = ("Google_", "Facebook_", "LoginWithAmazon_", "SignInWithApple_")
    for user in result.get("Users", []):
        username: str = user.get("Username", "")
        if not any(username.startswith(p) for p in federated_prefixes):
            return user
    return None


def _link_provider(native_username: str, provider_name: str, provider_user_id: str) -> None:
    """Link the federated identity to the existing native Cognito user."""
    _client().admin_link_provider_for_user(
        UserPoolId=USER_POOL_ID,
        DestinationUser={
            "ProviderName": "Cognito",
            "ProviderAttributeName": "Username",
            "ProviderAttributeValue": native_username,
        },
        SourceUser={
            "ProviderName": provider_name,
            "ProviderAttributeName": "Cognito_Subject",
            "ProviderAttributeValue": provider_user_id,
        },
    )


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    trigger: str = event.get("triggerSource", "")

    if not trigger.startswith("PreSignUp_ExternalProvider"):
        return event

    email: str = event.get("request", {}).get("userAttributes", {}).get("email", "").strip()
    if not email:
        logger.warning("PreSignUp_ExternalProvider fired without an email attribute; skipping link")
        return event

    # event["userName"] is "<ProviderName>_<ProviderUserId>", e.g. "Google_1234567890"
    raw_username: str = event.get("userName", "")
    parts = raw_username.split("_", 1)
    if len(parts) != 2:
        logger.warning("Unexpected userName format '%s'; skipping link", raw_username)
        return event

    provider_name, provider_user_id = parts[0], parts[1]

    try:
        native = _find_native_user(email)
        if native is None:
            logger.info(
                "No native user found for email=%s provider=%s; proceeding with new federated identity",
                email,
                provider_name,
            )
            return event

        native_username = native["Username"]
        logger.info(
            "Linking %s identity to native user '%s' for email=%s",
            provider_name,
            native_username,
            email,
        )
        _link_provider(native_username, provider_name, provider_user_id)
        logger.info("Link succeeded for email=%s", email)

    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "AliasExistsException":
            # Already linked — idempotent, nothing to do.
            logger.info("Provider already linked for email=%s; no-op", email)
        else:
            # Log but do NOT re-raise — a linking failure must not block sign-in.
            logger.exception("AdminLinkProviderForUser failed for email=%s: %s", email, exc)
    except Exception:  # noqa: BLE001
        logger.exception("Unexpected error during account linking for email=%s", email)

    return event
