"""Shared plan and module-access policy for backend clients."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone


PLAN_CATALOG = {
    "free": {
        "code": "free",
        "name": "Free",
        "price": "0 DT",
        "period": "forever",
        "description": "Coordinate workflows and product evaluation.",
        "manual_approval": False,
        "support_level": "Standard support",
        "modules": {
            "coordinates": True,
            "raster": False,
            "raster_georeferencing": False,
            "vector": False,
            "ai": False,
            "online_demos": True,
            "download": True,
        },
        "limitations": [
            "Raster and Vector desktop workspaces remain locked.",
            "Create and verify an account before using desktop coordinate tools.",
        ],
    },
    "plus": {
        "code": "plus",
        "name": "Plus",
        "price": "100 DT",
        "period": "per month",
        "description": "Full core GIS workflow access after manual approval.",
        "manual_approval": True,
        "support_level": "Priority account validation",
        "modules": {
            "coordinates": True,
            "raster": True,
            "raster_georeferencing": True,
            "vector": False,
            "ai": False,
            "online_demos": True,
            "download": True,
        },
        "limitations": [
            "Activation is completed manually after payment confirmation.",
        ],
    },
    "pro": {
        "code": "pro",
        "name": "Pro",
        "price": "200 DT",
        "period": "per month",
        "description": "Core GIS access plus early-access and direct setup support.",
        "manual_approval": True,
        "support_level": "Direct setup and workflow support",
        "modules": {
            "coordinates": True,
            "raster": True,
            "raster_georeferencing": True,
            "vector": True,
            "ai": True,
            "online_demos": True,
            "download": True,
        },
        "limitations": [
            "Activation is completed manually after payment confirmation.",
            "Early-access tools are released progressively.",
        ],
    },
    "admin": {
        "code": "admin",
        "name": "Admin",
        "price": None,
        "period": None,
        "description": "Administrator access to every available module.",
        "manual_approval": False,
        "support_level": "Administrator",
        "modules": {
            "coordinates": True,
            "raster": True,
            "raster_georeferencing": True,
            "vector": True,
            "ai": True,
            "online_demos": True,
            "download": True,
        },
        "limitations": [],
    },
}


def public_plans() -> list[dict]:
    """Return customer-facing plans without the administrator entry."""
    return [deepcopy(PLAN_CATALOG[code]) for code in ("free", "plus", "pro")]


def active_plan_code(user: dict) -> str:
    """Return the currently usable plan code for module access."""
    if user.get("role") == "admin":
        return "admin"

    if user.get("account_state", "active") != "active":
        return "free"

    active_plan = str(user.get("active_plan") or "").strip().lower()
    if active_plan in {"plus", "pro"}:
        return active_plan if is_subscription_active(user) else "free"
    if active_plan == "free":
        return "free"

    # Legacy compatibility for accounts created before subscription columns.
    if user.get("status") != "paid":
        return "free"
    selected = str(user.get("payment_plan") or "").strip().lower()
    return selected if selected in {"plus", "pro"} else "plus"


def is_subscription_active(user: dict) -> bool:
    """Return True when a paid user has a non-expired active subscription."""

    if user.get("role") == "admin":
        return True

    plan = str(user.get("active_plan") or "").strip().lower()
    if plan == "free":
        return False
    if plan not in {"plus", "pro"}:
        return False
    if str(user.get("subscription_status") or "").strip().lower() != "active":
        return False
    expires_at = _parse_datetime(user.get("subscription_expires_at"))
    return bool(expires_at and expires_at > datetime.now(timezone.utc))


def can_access_module(user: dict, module_name: str) -> bool:
    """Return whether the user can open a named module right now."""

    plan_code = active_plan_code(user)
    plan = PLAN_CATALOG.get(plan_code, PLAN_CATALOG["free"])
    return bool(plan["modules"].get(module_name, False))


def days_remaining(user: dict) -> int:
    """Return whole remaining subscription days, never negative."""

    expires_at = _parse_datetime(user.get("subscription_expires_at"))
    if not expires_at:
        return 0
    seconds = (expires_at - datetime.now(timezone.utc)).total_seconds()
    return max(0, int(seconds // 86400))


def unlocked_modules(user: dict) -> list[str]:
    """Return module codes available for the user's current plan."""

    plan = PLAN_CATALOG.get(active_plan_code(user), PLAN_CATALOG["free"])
    return [code for code, allowed in plan["modules"].items() if allowed]


def dashboard_for_user(user: dict) -> dict:
    """Build the safe account-dashboard payload consumed by the website."""
    plan_code = active_plan_code(user)
    plan = deepcopy(PLAN_CATALOG[plan_code])
    modules = [
        {
            "code": code,
            "available": bool(available),
        }
        for code, available in plan["modules"].items()
    ]
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "account_state": user.get("account_state") or "active",
        "payment_status": user.get("status") or "awaiting_payment",
        "active_plan": plan_code,
        "stored_active_plan": user.get("active_plan") or "free",
        "subscription_status": user.get("subscription_status") or "inactive",
        "subscription_started_at": _iso_datetime(user.get("subscription_started_at")),
        "subscription_expires_at": _iso_datetime(user.get("subscription_expires_at")),
        "days_remaining": days_remaining(user),
        "requested_plan": user.get("requested_plan"),
        "last_payment_id": user.get("last_payment_id"),
        "email_verified": bool(user.get("email_verified")),
        "avatar_path": user.get("avatar_path"),
        "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
        "support_level": plan["support_level"],
        "module_access": modules,
        "unlocked_modules": unlocked_modules(user),
    }


def _parse_datetime(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso_datetime(value) -> str | None:
    parsed = _parse_datetime(value)
    return parsed.isoformat() if parsed else None
