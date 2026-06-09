"""Manual bank-transfer payment and subscription routes."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from access_policy import dashboard_for_user
from admin_routes import get_current_user, require_admin
from database import get_db
from models import ApiResponse, PaymentNoteRequest, PaymentRejectRequest, PaymentRequestCreate
from rate_limit import enforce_rate_limit


router = APIRouter(tags=["Payments"])


@router.post("/me/payments")
def create_payment_request(
    payload: PaymentRequestCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Create or return one pending manual bank-transfer request."""

    enforce_rate_limit(request, "payment_request", str(current_user["id"]))
    if current_user["role"] == "admin":
        return {
            "ok": False,
            "message": "Administrator accounts already have full access.",
        }

    with get_db() as conn:
        plan = conn.execute(
            """
            SELECT code, name, price_tnd, duration_days
            FROM plans
            WHERE code = %s
              AND active = TRUE
            """,
            (payload.plan_code,),
        ).fetchone()
        if not plan:
            return {
                "ok": False,
                "message": "Invalid plan code.",
            }

        existing = conn.execute(
            """
            SELECT p.*, pl.name AS plan_name, u.username, u.email
            FROM payments p
            JOIN plans pl ON pl.code = p.plan_code
            JOIN app_users u ON u.id = p.user_id
            WHERE p.user_id = %s
              AND p.plan_code = %s
              AND p.status = 'pending'
            ORDER BY p.created_at DESC
            LIMIT 1
            """,
            (current_user["id"], payload.plan_code),
        ).fetchone()
        if existing:
            return {
                "ok": True,
                "message": "Paiement en attente de validation.",
                "payment": payment_to_public(existing),
                "duplicate_pending": True,
            }

        bank_reference = _bank_reference(payload.plan_code, current_user["id"])
        payment = conn.execute(
            """
            INSERT INTO payments (
                user_id,
                plan_code,
                amount,
                currency,
                payment_method,
                bank_reference,
                proof_url,
                status,
                notes
            )
            VALUES (%s, %s, %s, 'TND', 'bank_transfer', %s, %s, 'pending', %s)
            RETURNING *
            """,
            (
                current_user["id"],
                payload.plan_code,
                plan["price_tnd"],
                bank_reference,
                payload.proof_url,
                payload.notes,
            ),
        ).fetchone()
        payment = {
            **payment,
            "plan_name": plan["name"],
            "username": current_user.get("username"),
            "email": current_user.get("email"),
        }

    return {
        "ok": True,
        "message": "Votre demande de paiement a été créée.",
        "payment": payment_to_public(payment),
        "duplicate_pending": False,
    }


@router.get("/me/payments")
def my_payment_history(current_user: dict = Depends(get_current_user)):
    """Return the signed-in user's own payment history."""

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT p.*, pl.name AS plan_name, u.username, u.email
            FROM payments p
            JOIN plans pl ON pl.code = p.plan_code
            JOIN app_users u ON u.id = p.user_id
            WHERE p.user_id = %s
            ORDER BY p.created_at DESC
            """,
            (current_user["id"],),
        ).fetchall()

    return {
        "ok": True,
        "payments": [payment_to_public(row) for row in rows],
    }


@router.get("/me/subscription")
def my_subscription(current_user: dict = Depends(get_current_user)):
    """Return current subscription/access summary for the signed-in user."""

    return {
        "ok": True,
        "subscription": dashboard_for_user(current_user),
    }


@router.get("/admin/payments")
def admin_payments(
    status: str | None = Query(default=None, max_length=20),
    _: dict = Depends(require_admin),
):
    """Return payment rows for the admin dashboard."""

    params = []
    where = ""
    if status:
        normalized = status.strip().lower()
        if normalized not in {"pending", "approved", "rejected"}:
            raise HTTPException(status_code=400, detail="Invalid payment status.")
        where = "WHERE p.status = %s"
        params.append(normalized)

    with get_db() as conn:
        rows = conn.execute(
            f"""
            SELECT p.*, pl.name AS plan_name, u.username, u.email
            FROM payments p
            JOIN plans pl ON pl.code = p.plan_code
            JOIN app_users u ON u.id = p.user_id
            {where}
            ORDER BY p.created_at DESC
            """,
            tuple(params),
        ).fetchall()

    return {
        "ok": True,
        "payments": [payment_to_public(row) for row in rows],
    }


@router.get("/admin/users/{user_id}/payments")
def admin_user_payments(user_id: int, _: dict = Depends(require_admin)):
    """Return all payments for one user."""

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT p.*, pl.name AS plan_name, u.username, u.email
            FROM payments p
            JOIN plans pl ON pl.code = p.plan_code
            JOIN app_users u ON u.id = p.user_id
            WHERE p.user_id = %s
            ORDER BY p.created_at DESC
            """,
            (user_id,),
        ).fetchall()

    return {
        "ok": True,
        "payments": [payment_to_public(row) for row in rows],
    }


@router.patch("/admin/payments/{payment_id}/approve", response_model=ApiResponse)
def approve_payment(payment_id: int, admin_user: dict = Depends(require_admin)):
    """Approve one payment row; database triggers activate subscription."""

    with get_db() as conn:
        payment = conn.execute(
            """
            SELECT id, status
            FROM payments
            WHERE id = %s
            FOR UPDATE
            """,
            (payment_id,),
        ).fetchone()
        if not payment:
            return ApiResponse(ok=False, message="Payment not found.")
        if payment["status"] == "approved":
            return ApiResponse(ok=True, message="Paiement déjà validé.")

        conn.execute(
            """
            UPDATE payments
            SET status = 'approved',
                approved_at = COALESCE(approved_at, NOW()),
                approved_by = %s
            WHERE id = %s
            """,
            (admin_user["id"], payment_id),
        )

    return ApiResponse(ok=True, message="Paiement validé. L'abonnement a été activé automatiquement.")


@router.patch("/admin/payments/{payment_id}/reject", response_model=ApiResponse)
def reject_payment(
    payment_id: int,
    payload: PaymentRejectRequest,
    _: dict = Depends(require_admin),
):
    """Reject one payment row and keep a note for the admin/user history."""

    with get_db() as conn:
        payment = conn.execute(
            """
            SELECT id, status
            FROM payments
            WHERE id = %s
            FOR UPDATE
            """,
            (payment_id,),
        ).fetchone()
        if not payment:
            return ApiResponse(ok=False, message="Payment not found.")
        if payment["status"] == "approved":
            return ApiResponse(ok=False, message="Approved payments cannot be rejected.")

        conn.execute(
            """
            UPDATE payments
            SET status = 'rejected',
                notes = %s
            WHERE id = %s
            """,
            (payload.notes.strip(), payment_id),
        )

    return ApiResponse(ok=True, message="Paiement refusé. Veuillez contacter le support.")


@router.patch("/admin/payments/{payment_id}/note", response_model=ApiResponse)
def update_payment_note(
    payment_id: int,
    payload: PaymentNoteRequest,
    _: dict = Depends(require_admin),
):
    """Update the admin note attached to a payment."""

    with get_db() as conn:
        result = conn.execute(
            """
            UPDATE payments
            SET notes = %s
            WHERE id = %s
            RETURNING id
            """,
            (payload.notes.strip(), payment_id),
        ).fetchone()

    if not result:
        return ApiResponse(ok=False, message="Payment not found.")
    return ApiResponse(ok=True, message="Note mise à jour.")


def payment_to_public(row: dict) -> dict:
    """Return a JSON-safe payment object."""

    return {
        "id": row.get("id"),
        "user_id": row.get("user_id"),
        "username": row.get("username"),
        "email": row.get("email"),
        "plan_code": row.get("plan_code"),
        "plan_name": row.get("plan_name"),
        "amount": _decimal_to_float(row.get("amount")),
        "currency": row.get("currency") or "TND",
        "payment_method": row.get("payment_method") or "bank_transfer",
        "bank_reference": row.get("bank_reference"),
        "proof_url": row.get("proof_url"),
        "status": row.get("status"),
        "paid_at": _iso(row.get("paid_at")),
        "approved_at": _iso(row.get("approved_at")),
        "approved_by": row.get("approved_by"),
        "notes": row.get("notes"),
        "created_at": _iso(row.get("created_at")),
    }


def _bank_reference(plan_code: str, user_id: int) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"GMP-{plan_code.upper()}-{user_id}-{stamp}"


def _iso(value) -> str | None:
    if not value:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _decimal_to_float(value):
    if isinstance(value, Decimal):
        return float(value)
    return value
