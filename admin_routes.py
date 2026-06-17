"""Administrator-only account management routes."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from database import get_db
from models import AdminSubscriptionRenewRequest, ApiResponse, StatusUpdateRequest
from security import decode_access_token
from access_policy import active_plan_code, can_access_module, days_remaining, subscription_diagnostic

router = APIRouter(prefix="/admin", tags=["Admin"])

bearer_scheme = HTTPBearer()

VALID_STATUSES = {
    "awaiting_payment",
    "approved",
    "paid",
    "unpaid",
}

SESSION_REPLACED_DETAIL = (
    "This account is already open on another machine. "
    "For your privacy, this session was closed because the account can only be used on one machine at a time."
)
SESSION_INVALID_DETAIL = "Your account session is no longer valid. Sign in again."


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """Decode the bearer token and load the current database user."""
    token = credentials.credentials
    payload = decode_access_token(token)

    user_id = payload.get("sub")
    session_id = payload.get("sid")

    if not user_id or not session_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    # The token only stores a user ID, so load fresh role/status information on
    # every protected request. The session ID enforces one active machine.
    with get_db() as conn:
        user = conn.execute(
            """
            SELECT u.id, u.username, u.email, u.role, u.status, u.account_state,
                   u.payment_plan, u.requested_plan, u.active_plan,
                   u.subscription_status, u.subscription_started_at,
                   u.subscription_expires_at, u.last_payment_id,
                   u.email_verified, u.avatar_path, u.created_at,
                   s.id AS session_id,
                    s.revoked_at AS session_revoked_at,
                    s.revoked_reason AS session_revoked_reason,
                    EXISTS (
                        SELECT 1 FROM payments p
                        WHERE p.user_id = u.id
                          AND p.status = 'pending'
                    ) AS pending_payment,
                    (
                        SELECT p.id FROM payments p
                        WHERE p.user_id = u.id
                        ORDER BY p.created_at DESC, p.id DESC
                        LIMIT 1
                    ) AS latest_payment_id,
                    (
                        SELECT p.status FROM payments p
                        WHERE p.user_id = u.id
                        ORDER BY p.created_at DESC, p.id DESC
                        LIMIT 1
                    ) AS last_payment_status
            FROM app_users u
            LEFT JOIN app_sessions s
              ON s.id = %s
             AND s.user_id = u.id
            WHERE u.id = %s
            """,
            (str(session_id), int(user_id)),
        ).fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="User not found.")
        if not user.get("session_id"):
            raise HTTPException(status_code=401, detail=SESSION_INVALID_DETAIL)
        if user.get("session_revoked_at"):
            detail = (
                SESSION_REPLACED_DETAIL
                if user.get("session_revoked_reason") == "replaced_by_new_login"
                else SESSION_INVALID_DETAIL
            )
            raise HTTPException(status_code=401, detail=detail)
        if user.get("account_state", "active") != "active":
            raise HTTPException(status_code=401, detail="Account is unavailable.")

        conn.execute(
            """
            UPDATE app_sessions
            SET last_seen_at = NOW()
            WHERE id = %s
            """,
            (str(session_id),),
        )

    return user


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Require the authenticated account to have administrator role."""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")

    return current_user


def public_user(user: dict) -> dict:
    """Return a JSON-safe user object for admin table clients."""
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "status": str(user["status"] or "").strip().lower() or "awaiting_payment",
        "account_state": user.get("account_state") or "active",
        "payment_plan": user.get("payment_plan") or "free",
        "requested_plan": user.get("requested_plan"),
        "active_plan": active_plan_code(user),
        "stored_active_plan": user.get("active_plan") or "free",
        "subscription_status": user.get("subscription_status") or "inactive",
        "subscription_started_at": user["subscription_started_at"].isoformat() if user.get("subscription_started_at") else None,
        "subscription_expires_at": user["subscription_expires_at"].isoformat() if user.get("subscription_expires_at") else None,
        "last_payment_id": user.get("last_payment_id"),
        "pending_payment": bool(user.get("pending_payment")),
        "latest_payment_id": user.get("latest_payment_id"),
        "last_payment_status": user.get("last_payment_status"),
        "subscription_warning": subscription_diagnostic(user),
        "days_remaining": days_remaining(user),
        "modules": {
            "coordinates": can_access_module(user, "coordinates"),
            "raster": can_access_module(user, "raster"),
            "vector": can_access_module(user, "vector"),
            "ai": can_access_module(user, "ai"),
        },
        "email_verified": bool(user["email_verified"]),
        "avatar_path": user.get("avatar_path"),
        "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
    }


@router.get("/users")
def list_users(_: dict = Depends(require_admin)):
    """List all accounts for the admin dashboard."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, username, email, role, status, account_state,
                   payment_plan, requested_plan, active_plan,
                   subscription_status, subscription_started_at,
                   subscription_expires_at, last_payment_id,
                   email_verified, avatar_path, created_at,
                   EXISTS (
                       SELECT 1 FROM payments p
                       WHERE p.user_id = app_users.id
                         AND p.status = 'pending'
                   ) AS pending_payment,
                   (
                       SELECT p.id FROM payments p
                       WHERE p.user_id = app_users.id
                       ORDER BY p.created_at DESC, p.id DESC
                       LIMIT 1
                   ) AS latest_payment_id,
                   (
                       SELECT p.status FROM payments p
                       WHERE p.user_id = app_users.id
                       ORDER BY p.created_at DESC, p.id DESC
                       LIMIT 1
                   ) AS last_payment_status
            FROM app_users
            ORDER BY id ASC
            """
        ).fetchall()

    return {
        "ok": True,
        "users": [public_user(row) for row in rows],
    }


@router.patch("/users/{user_id}/status", response_model=ApiResponse)
def update_user_status(
    user_id: int,
    payload: StatusUpdateRequest,
    _: dict = Depends(require_admin),
):
    """Update a non-admin user's payment/access status."""
    status = payload.status.strip().lower()
    payment_plan = (payload.payment_plan or "").strip().lower()

    if status not in VALID_STATUSES:
        return ApiResponse(ok=False, message="Invalid status.")
    if status in {"paid", "approved"}:
        return ApiResponse(ok=False, message="Approve a payment instead. Subscriptions are activated by the database trigger.")
    if payment_plan and payment_plan not in {"free", "plus", "pro"}:
        return ApiResponse(ok=False, message="Invalid plan.")

    with get_db() as conn:
        # Read role first so the administrator account cannot be downgraded.
        user = conn.execute(
            """
            SELECT id, role
            FROM app_users
            WHERE id = %s
            """,
            (user_id,),
        ).fetchone()

        if not user:
            return ApiResponse(ok=False, message="User not found.")

        if user["role"] == "admin":
            return ApiResponse(ok=False, message="The administrator status cannot be changed.")

        # Status drives desktop access to paid Raster/Vector modules.
        conn.execute(
            """
            UPDATE app_users
            SET status = %s,
                payment_plan = CASE
                    WHEN %s <> '' THEN %s
                    ELSE payment_plan
                END
            WHERE id = %s
            """,
            (status, payment_plan, payment_plan, user_id),
        )

    return ApiResponse(ok=True, message=f"Status updated: {status}")


@router.post("/users/{user_id}/subscriptions/renew")
def renew_user_subscription(
    user_id: int,
    payload: AdminSubscriptionRenewRequest,
    admin_user: dict = Depends(require_admin),
):
    """Create and approve a payment so the database trigger renews access."""
    plan_code = payload.plan_code.strip().lower()
    note = (payload.notes or "Admin subscription renewal").strip()

    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, role
            FROM app_users
            WHERE id = %s
            FOR UPDATE
            """,
            (user_id,),
        ).fetchone()
        if not user:
            return {"ok": False, "message": "User not found."}
        if user["role"] == "admin":
            return {"ok": False, "message": "Administrator accounts already have full access."}

        plan = conn.execute(
            """
            SELECT code, name, price_tnd
            FROM plans
            WHERE code = %s
              AND active = TRUE
            """,
            (plan_code,),
        ).fetchone()
        if not plan:
            return {"ok": False, "message": "Invalid plan code."}

        bank_reference = _admin_bank_reference(plan_code, user_id)
        payment = conn.execute(
            """
            INSERT INTO payments (
                user_id,
                plan_code,
                amount,
                currency,
                payment_method,
                bank_reference,
                status,
                notes
            )
            VALUES (%s, %s, %s, 'TND', 'admin_manual_renewal', %s, 'pending', %s)
            RETURNING id
            """,
            (
                user_id,
                plan_code,
                plan["price_tnd"],
                bank_reference,
                note,
            ),
        ).fetchone()

        conn.execute(
            """
            UPDATE payments
            SET status = 'approved',
                approved_at = COALESCE(approved_at, NOW()),
                approved_by = %s
            WHERE id = %s
            """,
            (admin_user["id"], payment["id"]),
        )

    return {
        "ok": True,
        "message": "Paiement validé. L'abonnement a été activé automatiquement.",
        "payment_id": payment["id"],
        "plan_code": plan_code,
    }


@router.delete("/users/{user_id}", response_model=ApiResponse)
def delete_user(
    user_id: int,
    _: dict = Depends(require_admin),
):
    """Delete a non-admin user account."""
    with get_db() as conn:
        # Protect the administrator account from accidental removal.
        user = conn.execute(
            """
            SELECT id, role
            FROM app_users
            WHERE id = %s
            """,
            (user_id,),
        ).fetchone()

        if not user:
            return ApiResponse(ok=False, message="User not found.")

        if user["role"] == "admin":
            return ApiResponse(ok=False, message="The administrator account cannot be deleted.")

        conn.execute(
            """
            DELETE FROM app_users
            WHERE id = %s
            """,
            (user_id,),
        )

    return ApiResponse(ok=True, message="User deleted successfully.")


def _admin_bank_reference(plan_code: str, user_id: int) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"GMP-ADMIN-{plan_code.upper()}-{user_id}-{stamp}"
