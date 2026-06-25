"""HTTP client for subscription-service internal provision APIs."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)


def _base_url() -> str:
    return os.environ.get("SUBSCRIPTION_API_URL", "").rstrip("/")


def _provision_secret() -> str:
    return os.environ.get("INTERNAL_PROVISION_SECRET", "")


def _request(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    timeout: float = 3.0,
) -> tuple[int, dict[str, Any] | None]:
    base = _base_url()
    secret = _provision_secret()
    if not base or not secret:
        logger.warning("SUBSCRIPTION_API_URL or INTERNAL_PROVISION_SECRET not configured")
        return 0, None

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        f"{base}{path}",
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-internal-provision-secret": secret,
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
            payload = json.loads(raw) if raw else {}
            return resp.status, payload if isinstance(payload, dict) else None
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        logger.error("subscription API HTTP error status=%s body=%s", exc.code, raw)
        return exc.code, None
    except Exception:
        logger.exception("subscription API request failed path=%s", path)
        return 0, None


def provision_signup(user_id: str, display_name: str | None = None) -> dict[str, Any] | None:
    """Create platform tenant + org + membership. Returns data dict on 201."""
    body: dict[str, Any] = {"userId": user_id}
    if display_name:
        body["displayName"] = display_name
    status, payload = _request("POST", "/internal/provision/signup", body)
    if status == 201 and payload and payload.get("status") == "success":
        data = payload.get("data")
        return data if isinstance(data, dict) else None
    return None


def get_org_config(org_id: str) -> dict[str, Any] | None:
    """Resolve platform tenant_id for an org. Returns data dict on 200."""
    status, payload = _request("GET", f"/internal/orgs/{org_id}/config")
    if status == 200 and payload and payload.get("status") == "success":
        data = payload.get("data")
        return data if isinstance(data, dict) else None
    return None
