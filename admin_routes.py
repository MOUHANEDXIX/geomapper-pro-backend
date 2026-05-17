"""Administrator-only account management routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from database import get_db
from models import ApiResponse, StatusUpdateRequest
from security import decode_access_token

router = APIRouter(prefix="/admin", tags=["Admin"])

bearer_scheme = HTTPBearer()

VALID_STATUSES = {
    "awaiting_payment",
    "paid",
    "unpaid",
}


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """Decode the bearer token and load the current database user."""
    token = credentials.credentials
    payload = decode_access_token(token)

    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    # The token only stores a user ID, so load fresh role/status information on
    # every protected request.
    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, username, email, role, status, email_verified, avatar_path, created_at
            FROM app_users
            WHERE id = %s
            """,
            (int(user_id),),
        ).fetchone()

    if not user:
        raise HTTPException(status_code=401, detail="User not found.")

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
        "status": user["status"],
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
            SELECT id, username, email, role, status, email_verified, avatar_path, created_at
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
    status = payload.status.strip()

    if status not in VALID_STATUSES:
        return ApiResponse(ok=False, message="Invalid status.")

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
            SET status = %s
            WHERE id = %s
            """,
            (status, user_id),
        )

    return ApiResponse(ok=True, message=f"Status updated: {status}")


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
