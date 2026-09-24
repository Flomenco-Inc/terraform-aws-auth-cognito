"""Unit tests for PreSignUp federated account linking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import index


def _external_event(*, email: str, verified: str = "true", username: str = "Google_123") -> dict:
    return {
        "triggerSource": "PreSignUp_ExternalProvider",
        "userPoolId": "us-east-1_test",
        "userName": username,
        "request": {
            "userAttributes": {
                "email": email,
                "email_verified": verified,
            }
        },
    }


def test_skips_when_email_not_verified():
    event = _external_event(email="a@example.com", verified="false")
    with patch.object(index, "_client") as client_factory:
        assert index.handler(event, None) is event
        client_factory.assert_not_called()


def test_links_when_native_exists_and_email_verified():
    event = _external_event(email="a@example.com", verified="true")
    cognito = MagicMock()
    cognito.list_users.return_value = {
        "Users": [{"Username": "native-uuid"}],
    }
    with patch.object(index, "_client", return_value=cognito):
        assert index.handler(event, None) is event
    cognito.admin_link_provider_for_user.assert_called_once()


def test_link_failure_emits_metric_when_native_exists():
    event = _external_event(email="a@example.com")
    cognito = MagicMock()
    cognito.list_users.return_value = {"Users": [{"Username": "native-uuid"}]}
    from botocore.exceptions import ClientError

    cognito.admin_link_provider_for_user.side_effect = ClientError(
        {"Error": {"Code": "InvalidParameterException", "Message": "boom"}},
        "AdminLinkProviderForUser",
    )
    with (
        patch.object(index, "_client", return_value=cognito),
        patch.object(index, "_emit_link_failure_metric") as emit,
    ):
        assert index.handler(event, None) is event
    emit.assert_called_once_with("Google", "InvalidParameterException")
