"""Website-facing plans, support, analytics, and account dashboard routes."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from access_policy import dashboard_for_user, public_plans
from admin_routes import get_current_user
from database import get_db
from email_service import EmailService
from models import AnalyticsEventRequest, ApiResponse, PlanRequest, SupportRequest
from rate_limit import enforce_rate_limit

router = APIRouter(tags=["Website"])
logger = logging.getLogger(__name__)


@router.get("/plans")
def plans():
    """Return the public plan catalog from the shared access policy."""
    return {
        "ok": True,
        "plans": public_plans(),
        "payment_mode": "manual_approval",
    }


@router.get("/me/dashboard")
def account_dashboard(current_user: dict = Depends(get_current_user)):
    """Return the signed-in user's safe account dashboard."""
    return {
        "ok": True,
        "dashboard": dashboard_for_user(current_user),
    }


@router.post("/me/plan-request")
def request_plan(
    payload: PlanRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Record the paid plan a user wants the support team to activate."""
    enforce_rate_limit(request, "plan_request", str(current_user["id"]))
    if current_user["role"] == "admin":
        return {
            "ok": False,
            "message": "Administrator accounts already have full access.",
        }

    with get_db() as conn:
        plan = conn.execute(
            """
            SELECT code, name, price_tnd
            FROM plans
            WHERE code = %s
              AND active = TRUE
            """,
            (payload.plan,),
        ).fetchone()
        if not plan:
            return {
                "ok": False,
                "message": "Invalid plan.",
            }

        existing = conn.execute(
            """
            SELECT bank_reference
            FROM payments
            WHERE user_id = %s
              AND plan_code = %s
              AND status = 'pending'
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (current_user["id"], payload.plan),
        ).fetchone()
        if existing:
            return {
                "ok": True,
                "message": f"Paiement en attente de validation. Référence: {existing['bank_reference']}",
                "bank_reference": existing["bank_reference"],
            }

        bank_reference = f"GMP-{payload.plan.upper()}-{current_user['id']}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        conn.execute(
            """
            INSERT INTO payments (
                user_id,
                plan_code,
                amount,
                currency,
                payment_method,
                bank_reference,
                status
            )
            VALUES (%s, %s, %s, 'TND', 'bank_transfer', %s, 'pending')
            """,
            (current_user["id"], payload.plan, plan["price_tnd"], bank_reference),
        )
        conn.execute(
            """
            UPDATE app_users
            SET requested_plan = %s,
                status = CASE
                    WHEN status IN ('paid', 'approved') THEN status
                    ELSE 'awaiting_payment'
                END
            WHERE id = %s
            """,
            (payload.plan, current_user["id"]),
        )

    return {
        "ok": True,
        "message": (
            f"Votre demande de paiement a été créée. Référence: {bank_reference}"
        ),
        "bank_reference": bank_reference,
    }


@router.post("/support", response_model=ApiResponse)
def submit_support(payload: SupportRequest, request: Request):
    """Store a support request and notify the configured support inbox."""
    email = str(payload.email).strip().lower()
    enforce_rate_limit(request, "support", email)

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO support_messages (name, email, subject, category, message)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                payload.name.strip(),
                email,
                payload.subject.strip(),
                payload.category,
                payload.message.strip(),
            ),
        )

    try:
        EmailService().send_support_notification(
            payload.name.strip(),
            email,
            payload.category,
            payload.subject.strip(),
            payload.message.strip(),
        )
    except Exception:
        # The database record is the source of truth. Mail notification failure
        # must not discard a user's support request or expose SMTP details.
        logger.exception("Stored support request but could not send notification")

    return ApiResponse(ok=True, message="Your support request was received. The GeoMapper Pro team will reply by email.")


@router.post("/analytics/events", response_model=ApiResponse)
def record_analytics_event(payload: AnalyticsEventRequest, request: Request):
    """Store a minimal anonymous website event when analytics is enabled."""
    if os.getenv("ANALYTICS_ENABLED", "true").strip().lower() in {"0", "false", "no"}:
        return ApiResponse(ok=True, message="Analytics disabled.")

    enforce_rate_limit(request, "analytics", payload.session_id)
    safe_metadata = payload.metadata or {}
    if len(json.dumps(safe_metadata)) > 2000:
        safe_metadata = {"truncated": True}

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO analytics_events (event_name, session_id, page, metadata)
            VALUES (%s, %s, %s, %s)
            """,
            (payload.event_name, payload.session_id, payload.page, json.dumps(safe_metadata)),
        )

    return ApiResponse(ok=True, message="Event recorded.")
