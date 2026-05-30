"""Shared plan and module-access policy for backend clients."""

from __future__ import annotations

from copy import deepcopy


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
            "vector": True,
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
    """Map legacy payment status and optional selected plan to one plan code."""
    if user.get("role") == "admin":
        return "admin"

    if user.get("account_state", "active") != "active":
        return "free"

    if user.get("status") != "paid":
        return "free"

    selected = str(user.get("payment_plan") or "").strip().lower()
    return selected if selected in {"plus", "pro"} else "plus"


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
        "requested_plan": user.get("requested_plan"),
        "email_verified": bool(user.get("email_verified")),
        "avatar_path": user.get("avatar_path"),
        "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
        "support_level": plan["support_level"],
        "module_access": modules,
    }
