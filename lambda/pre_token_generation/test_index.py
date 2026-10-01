"""Unit tests for the pre-token-generation trigger.

Run: cd lambda/pre_token_generation && MEMBERSHIPS_TABLE=test python -m pytest test_index.py
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any
from unittest.mock import patch

import pytest

os.environ.setdefault("MEMBERSHIPS_TABLE", "test-memberships")
sys.path.insert(0, os.path.dirname(__file__))

import index  # noqa: E402


def make_event(
    sub: str = "user-1",
    *,
    email: str | None = "person@example.com",
    email_verified: str | bool | None = "true",
) -> dict[str, Any]:
    attrs: dict[str, Any] = {"sub": sub}
    if email is not None:
        attrs["email"] = email
    if email_verified is not None:
        attrs["email_verified"] = email_verified
    return {
        "triggerSource": "TokenGeneration_Authentication",
        "request": {"userAttributes": attrs},
    }


def membership_row(org_id: str, role: str = "member", tenant_id: str | None = "tenant_1") -> dict:
    row: dict[str, Any] = {"PK": "user-1", "SK": org_id, "role": role}
    if tenant_id:
        row["tenant_id"] = tenant_id
    return row


def run_handler(rows: list[dict[str, Any]], event: dict[str, Any] | None = None) -> dict[str, Any]:
    with patch.object(index, "_fetch_user_rows", return_value=rows):
        return index.handler(event or make_event(), None)


def access_claims(result: dict[str, Any]) -> dict[str, Any]:
    return result["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"][
        "claimsToAddOrOverride"
    ]


def id_claims(result: dict[str, Any]) -> dict[str, Any]:
    return result["response"]["claimsAndScopeOverrideDetails"]["idTokenGeneration"][
        "claimsToAddOrOverride"
    ]


class TestActiveOrgBinding:
    def test_active_org_row_selects_the_bound_org(self):
        rows = [
            membership_row("org_a"),
            membership_row("org_b"),
            {"PK": "user-1", "SK": "ACTIVE_ORG", "org_id": "org_b"},
        ]
        claims = access_claims(run_handler(rows))
        assert claims["org_id"] == "org_b"
        assert claims["tenant_id"] == "tenant_1"
        assert claims["primary_org_id"] == "org_b"

    def test_stale_active_org_falls_back_to_first_membership(self):
        rows = [
            membership_row("org_a"),
            {"PK": "user-1", "SK": "ACTIVE_ORG", "org_id": "org_gone"},
        ]
        claims = access_claims(run_handler(rows))
        assert claims["org_id"] == "org_a"

    def test_no_selection_defaults_to_sole_membership(self):
        claims = access_claims(run_handler([membership_row("org_only")]))
        assert claims["org_id"] == "org_only"


class TestNonMembershipRows:
    def test_active_org_and_resolved_rows_are_not_memberships(self):
        rows = [
            membership_row("org_a"),
            {"PK": "user-1", "SK": "ACTIVE_ORG", "org_id": "org_a"},
            {"PK": "user-1", "SK": "RESOLVED_PERMISSIONS#org_a", "permissions": ["assets:read"]},
        ]
        result = run_handler(rows)
        memberships = json.loads(access_claims(result)["org_memberships"])
        assert [m["org_id"] for m in memberships] == ["org_a"]

    def test_resolved_grants_injected_for_active_org_only(self):
        rows = [
            membership_row("org_a"),
            membership_row("org_b"),
            {"PK": "user-1", "SK": "ACTIVE_ORG", "org_id": "org_b"},
            {
                "PK": "user-1",
                "SK": "RESOLVED_PERMISSIONS#org_b",
                "permissions": ["assets:read", "assets:write"],
                "teams": ["team_x"],
            },
            {"PK": "user-1", "SK": "RESOLVED_PERMISSIONS#org_a", "permissions": ["*:*"]},
        ]
        result = run_handler(rows)
        assert json.loads(access_claims(result)["permissions"]) == ["assets:read", "assets:write"]
        assert json.loads(access_claims(result)["teams"]) == ["team_x"]


class TestFailClosed:
    def test_lookup_failure_raises_and_denies_the_token(self):
        with patch.object(index, "_fetch_user_rows", side_effect=RuntimeError("ddb down")):
            with pytest.raises(RuntimeError):
                index.handler(make_event(), None)

    def test_missing_sub_raises(self):
        with pytest.raises(RuntimeError):
            index.handler({"triggerSource": "t", "request": {"userAttributes": {}}}, None)


class TestClaimSizeGuardrail:
    def test_oversized_permissions_are_shed_with_overflow_marker(self):
        huge_permissions = [f"resource{i}.subresource{i}:action{i}" for i in range(600)]
        rows = [
            membership_row("org_a"),
            {
                "PK": "user-1",
                "SK": "RESOLVED_PERMISSIONS#org_a",
                "permissions": huge_permissions,
            },
        ]
        result = run_handler(rows)
        claims = access_claims(result)
        assert "permissions" not in claims
        assert claims["permissions_overflow"] == "true"
        assert "permissions" not in id_claims(result)
        # Everything else survives the shed.
        assert claims["org_id"] == "org_a"
        assert len(json.dumps(claims)) <= index.ACCESS_CLAIMS_BYTE_BUDGET

    def test_small_permissions_stay_in_claims(self):
        rows = [
            membership_row("org_a"),
            {"PK": "user-1", "SK": "RESOLVED_PERMISSIONS#org_a", "permissions": ["assets:read"]},
        ]
        claims = access_claims(run_handler(rows))
        assert json.loads(claims["permissions"]) == ["assets:read"]
        assert "permissions_overflow" not in claims


class TestAutoProvision:
    def test_empty_memberships_provisions_via_api(self):
        with patch.object(
            index,
            "_provision_via_api",
            return_value={"tenant_id": "tenant_new", "org_id": "org_new", "role": "OWNER"},
        ):
            claims = access_claims(run_handler([]))
        assert claims["org_id"] == "org_new"
        assert claims["tenant_id"] == "tenant_new"

    def test_provisioning_failure_denies_the_token(self):
        with patch.object(index, "_provision_via_api", return_value=None):
            with patch.object(index, "_fetch_user_rows", return_value=[]):
                with pytest.raises(RuntimeError, match="provisioning failed"):
                    index.handler(make_event(), None)


class TestAccessTokenEmailClaims:
    def test_email_and_verified_copied_onto_access_token(self):
        claims = access_claims(run_handler([membership_row("org_a")]))
        assert claims["email"] == "person@example.com"
        assert claims["email_verified"] == "true"

    def test_email_verified_false_normalized(self):
        event = make_event(email="a@b.co", email_verified="false")
        claims = access_claims(run_handler([membership_row("org_a")], event=event))
        assert claims["email"] == "a@b.co"
        assert claims["email_verified"] == "false"

    def test_missing_email_omits_email_claims(self):
        event = make_event(email=None, email_verified=None)
        claims = access_claims(run_handler([membership_row("org_a")], event=event))
        assert "email" not in claims
        assert "email_verified" not in claims


class TestByteBudgetUnits:
    def test_budget_measures_utf8_bytes_not_code_points(self):
        # Multi-byte team names: each char is 1 code point but 3 UTF-8 bytes,
        # so a code-point count would stay under budget while bytes exceed it.
        wide_permissions = ["資産:読取" * 200 for _ in range(4)]
        rows = [
            membership_row("org_a"),
            {
                "PK": "user-1",
                "SK": "RESOLVED_PERMISSIONS#org_a",
                "permissions": wide_permissions,
            },
        ]
        result = run_handler(rows)
        claims = access_claims(result)
        assert "permissions" not in claims
        assert claims["permissions_overflow"] == "true"


def _identities_json(*providers: tuple[str, str]) -> str:
    items = []
    for i, (name, ptype) in enumerate(providers):
        items.append(
            {
                "dateCreated": str(1_700_000_000_000 + i),
                "userId": f"id-{i}",
                "providerName": name,
                "providerType": ptype,
                "issuer": None,
                "primary": "true" if i == 0 else "false",
            }
        )
    return json.dumps(items)


class TestSsoEnforceBypass:
    def test_pipeline_service_email_bypasses_enforce(self):
        event = make_event(email="pipeline-service@flomenco.com")
        with patch.object(index, "discover_sso_enforced", return_value=True) as discover:
            claims = access_claims(run_handler([membership_row("org_a")], event=event))
        discover.assert_not_called()
        assert claims["org_id"] == "org_a"

    def test_human_enforced_email_still_denied(self):
        event = make_event(email="ryan@flomenco.com")
        with patch.object(index, "discover_sso_enforced", return_value=True):
            with pytest.raises(RuntimeError, match="SSO is enforced"):
                run_handler([membership_row("org_a")], event=event)

    def test_google_hosted_auth_denied_while_social_still_linked(self):
        event = make_event(email="ryan@flomenco.com")
        event["triggerSource"] = "TokenGeneration_HostedAuth"
        event["userName"] = "Google_117168582925268021715"
        event["request"]["userAttributes"]["identities"] = _identities_json(
            ("Google", "Google"),
            ("ssod2294fa97c10ce68df76d3530206c", "OIDC"),
        )
        with patch.object(index, "discover_sso_enforced", return_value=True):
            with pytest.raises(RuntimeError, match="SSO is enforced"):
                run_handler([membership_row("org_a")], event=event)

    def test_hosted_auth_allowed_after_social_unlinked(self):
        event = make_event(email="ryan@flomenco.com")
        event["triggerSource"] = "TokenGeneration_HostedAuth"
        event["userName"] = "Google_117168582925268021715"
        event["request"]["userAttributes"]["identities"] = _identities_json(
            ("ssod2294fa97c10ce68df76d3530206c", "OIDC"),
        )
        with patch.object(index, "discover_sso_enforced", return_value=True) as discover:
            claims = access_claims(run_handler([membership_row("org_a")], event=event))
        discover.assert_not_called()
        assert claims["org_id"] == "org_a"

    def test_enterprise_username_bypasses_enforce(self):
        event = make_event(email="ryan@flomenco.com")
        event["userName"] = "ssod2294fa97c10ce68df76d3530206c_00u1ojo30auGV5Kjt1d8"
        with patch.object(index, "discover_sso_enforced", return_value=True) as discover:
            claims = access_claims(run_handler([membership_row("org_a")], event=event))
        discover.assert_not_called()
        assert claims["org_id"] == "org_a"


    def test_refresh_tokens_allowed_when_enterprise_linked_no_social(self):
        event = make_event(email="ryan@flomenco.com")
        event["triggerSource"] = "TokenGeneration_RefreshTokens"
        event["userName"] = "native-uuid"
        # Linked Okta on a native profile is non-primary in identities.
        event["request"]["userAttributes"]["identities"] = json.dumps(
            [
                {
                    "dateCreated": "1700000000000",
                    "userId": "okta-sub",
                    "providerName": "ssod2294fa97c10ce68df76d3530206c",
                    "providerType": "OIDC",
                    "issuer": None,
                    "primary": "false",
                }
            ]
        )
        with patch.object(index, "discover_sso_enforced", return_value=True) as discover:
            claims = access_claims(run_handler([membership_row("org_a")], event=event))
        discover.assert_not_called()
        assert claims["org_id"] == "org_a"

    def test_password_authentication_denied_even_when_enterprise_linked(self):
        event = make_event(email="ryan@flomenco.com")
        event["triggerSource"] = "TokenGeneration_Authentication"
        event["userName"] = "native-uuid"
        event["request"]["userAttributes"]["identities"] = json.dumps(
            [
                {
                    "dateCreated": "1700000000000",
                    "userId": "okta-sub",
                    "providerName": "ssod2294fa97c10ce68df76d3530206c",
                    "providerType": "OIDC",
                    "issuer": None,
                    "primary": "false",
                }
            ]
        )
        with patch.object(index, "discover_sso_enforced", return_value=True):
            with pytest.raises(RuntimeError, match="SSO is enforced"):
                run_handler([membership_row("org_a")], event=event)

    def test_uuid_username_with_primary_enterprise_identity_is_enterprise(self):
        """HostedAuth sometimes passes sub UUID as userName — still enterprise."""
        event = make_event(email="ryan@flomenco.com", email_verified="false")
        event["triggerSource"] = "TokenGeneration_HostedAuth"
        event["userName"] = "5448c418-60b1-70f1-db1c-c8559b43edd8"
        event["request"]["userAttributes"]["identities"] = _identities_json(
            ("ssod2294fa97c10ce68df76d3530206c", "OIDC"),
        )
        assert index._is_enterprise_sso_user(event, event["request"]["userAttributes"]) is True

    def test_google_primary_with_linked_okta_is_not_enterprise(self):
        event = make_event(email="ryan@flomenco.com")
        event["userName"] = "Google_117168582925268021715"
        event["request"]["userAttributes"]["identities"] = _identities_json(
            ("Google", "Google"),
            ("ssod2294fa97c10ce68df76d3530206c", "OIDC"),
        )
        assert index._is_enterprise_sso_user(event, event["request"]["userAttributes"]) is False

    def test_enterprise_with_personal_org_still_merges_peer_memberships(self):
        """PostConfirmation JIT must not block adopt from the Google peer."""
        personal = membership_row(
            "org_personal", role="OWNER", tenant_id="tenant_personal"
        )
        personal["PK"] = "sso-user"
        peer_rows = [
            membership_row("org_paid", role="OWNER", tenant_id="tenant_paid"),
            {"PK": "google-peer", "SK": "ACTIVE_ORG", "org_id": "org_paid"},
        ]
        event = make_event(sub="sso-user", email="ryan@flomenco.com", email_verified="false")
        event["triggerSource"] = "TokenGeneration_HostedAuth"
        event["userPoolId"] = "us-east-1_test"
        event["userName"] = "ssod2294fa97c10ce68df76d3530206c_okta1"
        event["request"]["userAttributes"]["identities"] = _identities_json(
            ("ssod2294fa97c10ce68df76d3530206c", "OIDC"),
        )

        fetch_calls = {"n": 0}

        def fake_fetch(uid: str):
            fetch_calls["n"] += 1
            if uid == "sso-user":
                # After adopt, handler re-fetches — return merged rows.
                if fetch_calls["n"] == 1:
                    return [personal]
                return [
                    personal,
                    {**peer_rows[0], "PK": "sso-user"},
                    {**peer_rows[1], "PK": "sso-user"},
                ]
            return peer_rows

        with (
            patch.object(index, "_fetch_user_rows", side_effect=fake_fetch),
            patch.object(index, "discover_sso_provider_for_link", return_value="ssod2294fa97c10ce68df76d3530206c"),
            patch.object(index, "_cognito_subs_for_email", return_value=["google-peer"]),
            patch.object(index, "_adopt_memberships_from_peers", return_value=[{}]) as adopt,
        ):
            result = index.handler(event, None)

        adopt.assert_called_once_with("sso-user", ["google-peer"])
        claims = access_claims(result)
        assert claims["org_id"] == "org_paid"
        assert claims["tenant_id"] == "tenant_paid"

