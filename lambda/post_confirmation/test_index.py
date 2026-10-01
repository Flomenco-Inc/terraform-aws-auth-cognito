"""Unit tests for post-confirmation enterprise SSO skip.

Run: cd lambda/post_confirmation && python -m pytest test_index.py
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import index  # noqa: E402


def make_event(
    *,
    sub: str = "user-1",
    user_name: str = "user-1",
    email: str = "a@b.co",
    identities: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    attrs: dict[str, Any] = {"sub": sub, "email": email}
    if identities is not None:
        attrs["identities"] = json.dumps(identities)
    return {
        "triggerSource": "PostConfirmation_ConfirmSignUp",
        "userName": user_name,
        "request": {"userAttributes": attrs},
    }


class TestEnterpriseSkip:
    def test_sso_username_skips_provision(self):
        event = make_event(
            user_name="ssod2294fa97c10ce68df76d3530206c_okta1",
            sub="sso-sub",
        )
        with patch.object(index, "provision_signup") as provision:
            out = index.handler(event, None)
        provision.assert_not_called()
        assert out is event

    def test_uuid_username_with_primary_enterprise_identity_skips(self):
        event = make_event(
            user_name="5448c418-60b1-70f1-db1c-c8559b43edd8",
            sub="5448c418-60b1-70f1-db1c-c8559b43edd8",
            identities=[
                {
                    "providerName": "ssod2294fa97c10ce68df76d3530206c",
                    "providerType": "OIDC",
                    "primary": "true",
                    "userId": "okta1",
                }
            ],
        )
        with patch.object(index, "provision_signup") as provision:
            index.handler(event, None)
        provision.assert_not_called()

    def test_google_user_still_provisions(self):
        event = make_event(
            user_name="Google_123",
            sub="google-sub",
            identities=[
                {
                    "providerName": "Google",
                    "providerType": "Google",
                    "primary": "true",
                    "userId": "123",
                }
            ],
        )
        with patch.object(
            index, "provision_signup", return_value={"tenantId": "t", "orgId": "o"}
        ) as provision:
            index.handler(event, None)
        provision.assert_called_once()
