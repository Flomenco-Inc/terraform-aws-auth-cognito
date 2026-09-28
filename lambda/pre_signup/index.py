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

Ops note: if a duplicate Google_* user already exists alongside a native user for
the same email, PreSignUp cannot merge them. Migrate memberships onto the native
sub, AdminDeleteUser the Google_* user, then have the user sign in with Google
again so this trigger re-links. See module README.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

METRIC_NAMESPACE = "Flo/Auth"
METRIC_LINK_FAILURE = "PreSignUpAccountLinkFailure"

# Cognito federated usernames: ProviderName_Subject. Enterprise Tenant IdPs use
# provider names ``sso`` + 29 hex (no underscore) so split("_", 1) still works.
_FEDERATED_PREFIXES = ("Google_", "Facebook_", "LoginWithAmazon_", "SignInWithApple_")
_ENTERPRISE_SSO_USERNAME = re.compile(r"^sso[a-f0-9]{29}_")
_ENTERPRISE_SSO_PROVIDER = re.compile(r"^sso[a-f0-9]{29}$")

_cognito: Any = None
_cloudwatch: Any = None


def _subscription_api_url() -> str:
    return os.environ.get("SUBSCRIPTION_API_URL", "").rstrip("/")


def _enterprise_link_authorized(email: str, provider_name: str) -> bool:
    """Only link enterprise IdPs when DNS-claimed IdP for the email matches.

    Prevents a customer IdP from attaching itself to an arbitrary Flo native
    account by asserting a verified email that belongs to another Tenant's user
    outside the IdP's claimed domain registry.
    """
    base = _subscription_api_url()
    if not base:
        logger.warning("SUBSCRIPTION_API_URL unset; denying enterprise account link")
        return False
    data = json.dumps({"email": email, "purpose": "link"}).encode("utf-8")
    req = urllib.request.Request(
        f"{base}/auth/sso/discover",
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
            payload = json.loads(raw) if raw else {}
    except Exception:
        logger.exception("SSO discover failed during enterprise link authorization")
        return False
    if not isinstance(payload, dict) or payload.get("status") != "success":
        return False
    data_obj = payload.get("data")
    if not isinstance(data_obj, dict):
        return False
    claimed = data_obj.get("providerName")
    return isinstance(claimed, str) and claimed == provider_name


def _client() -> Any:
    global _cognito
    if _cognito is None:
        _cognito = boto3.client("cognito-idp")
    return _cognito


def _cw() -> Any:
    global _cloudwatch
    if _cloudwatch is None:
        _cloudwatch = boto3.client("cloudwatch")
    return _cloudwatch


def _emit_link_failure_metric(provider_name: str, reason: str) -> None:
    """Best-effort CloudWatch metric when linking fails but a native user exists."""
    try:
        _cw().put_metric_data(
            Namespace=METRIC_NAMESPACE,
            MetricData=[
                {
                    "MetricName": METRIC_LINK_FAILURE,
                    "Value": 1.0,
                    "Unit": "Count",
                    "Dimensions": [
                        {"Name": "Provider", "Value": provider_name or "unknown"},
                        {"Name": "Reason", "Value": reason[:256] or "unknown"},
                    ],
                }
            ],
        )
    except Exception:  # noqa: BLE001
        logger.exception("Failed to emit %s metric", METRIC_LINK_FAILURE)


def _find_native_user(user_pool_id: str, email: str) -> dict[str, Any] | None:
    """Return the first native (non-federated) Cognito user with this email, or None."""
    result = _client().list_users(
        UserPoolId=user_pool_id,
        Filter=f'email = "{email}"',
        Limit=10,
    )
    for user in result.get("Users", []):
        username: str = user.get("Username", "")
        if any(username.startswith(p) for p in _FEDERATED_PREFIXES):
            continue
        if _ENTERPRISE_SSO_USERNAME.match(username):
            continue
        return user
    return None


def _parse_provider(raw_username: str) -> tuple[str, str] | None:
    """Return (providerName, providerUserId) from Cognito federated username."""
    if _ENTERPRISE_SSO_USERNAME.match(raw_username):
        provider_name = raw_username[:32]
        provider_user_id = raw_username[33:]
        if provider_user_id and _ENTERPRISE_SSO_PROVIDER.match(provider_name):
            return provider_name, provider_user_id
    parts = raw_username.split("_", 1)
    if len(parts) != 2:
        return None
    return parts[0], parts[1]


def _link_provider(user_pool_id: str, native_username: str, provider_name: str, provider_user_id: str) -> None:
    """Link the federated identity to the existing native Cognito user."""
    _client().admin_link_provider_for_user(
        UserPoolId=user_pool_id,
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


def _is_email_verified(attrs: dict[str, str]) -> bool:
    """True when the IdP asserts a verified email (Cognito uses string 'true')."""
    return attrs.get("email_verified", "").lower() == "true"


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    trigger: str = event.get("triggerSource", "")

    if not trigger.startswith("PreSignUp_ExternalProvider"):
        return event

    # Read the user pool ID from the trigger event rather than an env var to
    # avoid a Terraform cycle between the user pool and this Lambda.
    user_pool_id: str = event.get("userPoolId", "")
    if not user_pool_id:
        logger.warning("PreSignUp trigger fired without userPoolId; skipping link")
        return event

    attrs: dict[str, str] = event.get("request", {}).get("userAttributes", {}) or {}
    email: str = (attrs.get("email") or "").strip()
    if not email:
        logger.warning("PreSignUp_ExternalProvider fired without an email attribute; skipping link")
        return event

    if not _is_email_verified(attrs):
        logger.warning(
            "PreSignUp_ExternalProvider email=%s is not verified; skipping link "
            "(will not attach unverified IdP email to a native account)",
            email,
        )
        return event

    # event["userName"] is "<ProviderName>_<ProviderUserId>", e.g. "Google_1234567890"
    # or "sso{29hex}_{subject}" for Tenant Identity Providers.
    raw_username: str = event.get("userName", "")
    parsed = _parse_provider(raw_username)
    if parsed is None:
        logger.warning("Unexpected userName format '%s'; skipping link", raw_username)
        return event

    provider_name, provider_user_id = parsed
    native_existed = False

    # Enterprise IdPs: only link when the email domain's DNS-claimed IdP matches
    # this provider. Otherwise Cognito creates a distinct federated identity
    # (invite-only / no-access) instead of attaching to an unrelated native sub.
    if _ENTERPRISE_SSO_PROVIDER.match(provider_name):
        if not _enterprise_link_authorized(email, provider_name):
            logger.warning(
                "Denying enterprise AdminLinkProviderForUser for email=%s provider=%s "
                "(provider does not match DNS-claimed IdP for domain)",
                email,
                provider_name,
            )
            return event

    try:
        native = _find_native_user(user_pool_id, email)
        if native is None:
            logger.info(
                "No native user found for email=%s provider=%s; proceeding with new federated identity",
                email,
                provider_name,
            )
            return event

        native_existed = True
        native_username = native["Username"]
        logger.info(
            "Linking %s identity to native user '%s' for email=%s",
            provider_name,
            native_username,
            email,
        )
        _link_provider(user_pool_id, native_username, provider_name, provider_user_id)
        logger.info("Link succeeded for email=%s", email)

    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "AliasExistsException":
            # Already linked — idempotent, nothing to do.
            logger.info("Provider already linked for email=%s; no-op", email)
        else:
            # Log but do NOT re-raise — a linking failure must not block sign-in.
            logger.error(
                "AdminLinkProviderForUser failed for email=%s native_existed=%s: %s",
                email,
                native_existed,
                exc,
                exc_info=True,
            )
            if native_existed:
                _emit_link_failure_metric(provider_name, code or "ClientError")
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Unexpected error during account linking for email=%s native_existed=%s",
            email,
            native_existed,
            exc_info=True,
        )
        if native_existed:
            _emit_link_failure_metric(provider_name, type(exc).__name__)

    return event
