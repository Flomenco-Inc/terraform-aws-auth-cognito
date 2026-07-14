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


def make_event(sub: str = "user-1") -> dict[str, Any]:
    return {
        "triggerSource": "TokenGeneration_Authentication",
        "request": {"userAttributes": {"sub": sub}},
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
