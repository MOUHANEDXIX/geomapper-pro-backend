"""FastAPI application for GeoMapper Pro accounts and admin access.

The desktop app and website both use this service for registration, login,
email verification, profile updates, payment-status validation, and admin user
management.
"""

from __future__ import annotations

import os
import asyncio
from contextlib import suppress
import logging

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth_routes import generate_code, router as auth_router, user_to_public_dict
from admin_routes import get_current_user, router as admin_router
from database import cleanup_expired_unverified_users, get_db, init_default_admin
from email_service import EmailService
from models import ProfileUpdateRequest
from update_routes import router as update_router

app = FastAPI(
    title="GeoMapper Pro Backend",
    version="1.1.0",
)

logger = logging.getLogger(__name__)
_expired_user_cleanup_task: asyncio.Task | None = None


def cors_origins_from_env() -> list[str]:
    """Read comma-separated browser origins allowed to call the API."""
    raw_origins = os.getenv("BACKEND_CORS_ORIGINS", "*")
    origins = [
        origin.strip().rstrip("/")
        for origin in raw_origins.split(",")
        if origin.strip()
    ]
    return origins or ["*"]


cors_origins = cors_origins_from_env()
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials="*" not in cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    """Create the account table and ensure the configured admin exists."""
    init_default_admin()
    cleanup_expired_unverified_users()


@app.on_event("startup")
async def start_expired_user_cleanup():
    """Run periodic cleanup for accounts that never verified their first email."""
    global _expired_user_cleanup_task
    if _expired_user_cleanup_task is None or _expired_user_cleanup_task.done():
        _expired_user_cleanup_task = asyncio.create_task(_cleanup_expired_users_loop())


@app.on_event("shutdown")
async def stop_expired_user_cleanup():
    """Stop the periodic cleanup task during backend shutdown."""
    if _expired_user_cleanup_task is None:
        return

    _expired_user_cleanup_task.cancel()
    with suppress(asyncio.CancelledError):
        await _expired_user_cleanup_task


async def _cleanup_expired_users_loop():
    """Delete expired unverified signups once per minute."""
    while True:
        await asyncio.sleep(60)
        try:
            deleted = cleanup_expired_unverified_users()
            if deleted:
                logger.info("Deleted %s expired unverified account(s).", deleted)
        except Exception:
            logger.exception("Expired unverified account cleanup failed.")


@app.get("/")
def root():
    """Return a lightweight health check used by launchers and the website."""
    return {
        "ok": True,
        "message": "GeoMapper Pro backend is running.",
        "version": app.version,
    }


@app.get("/healthz")
def healthz():
    """Return a stable health check endpoint for deployment platforms."""
    return {
        "ok": True,
        "message": "GeoMapper Pro backend is healthy.",
        "version": app.version,
    }


@app.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    """Return the authenticated user's public account profile."""
    return {
        "ok": True,
        "user": {
            "id": current_user["id"],
            "username": current_user["username"],
            "email": current_user["email"],
            "role": current_user["role"],
            "status": current_user["status"],
            "email_verified": bool(current_user["email_verified"]),
            "avatar_path": current_user.get("avatar_path"),
            "created_at": current_user["created_at"].isoformat()
            if current_user.get("created_at")
            else None,
        },
    }


@app.patch("/me/profile")
def update_profile(
    payload: ProfileUpdateRequest,
    current_user: dict = Depends(get_current_user),
):
    """Update username/email/avatar and require re-verification when needed."""
    username = payload.username.strip()
    email = str(payload.email).strip().lower()
    avatar_path = payload.avatar_path
    user_id = current_user["id"]
    email_changed = (current_user.get("email") or "").lower() != email
    must_verify_email = current_user.get("role") != "admin" and email_changed

    code = None
    expires_at = None
    # Non-admin email changes must be verified before the account can sign in
    # with the new address.
    if must_verify_email:
        code, expires_at = generate_code()

    with get_db() as conn:
        # Keep username and email unique across every account except the one
        # currently being updated.
        existing = conn.execute(
            """
            SELECT id
            FROM app_users
            WHERE id <> %s
              AND (LOWER(username) = LOWER(%s) OR LOWER(email) = LOWER(%s))
            """,
            (user_id, username, email),
        ).fetchone()

        if existing:
            return {
                "ok": False,
                "message": "Username or email is already in use.",
            }

        # Reset email verification only when a normal user changed email.
        conn.execute(
            """
            UPDATE app_users
            SET username = %s,
                email = %s,
                avatar_path = %s,
                email_verified = CASE
                    WHEN %s THEN FALSE
                    ELSE email_verified
                END,
                email_verification_code = CASE
                    WHEN %s THEN %s
                    ELSE email_verification_code
                END,
                email_verification_expires_at = CASE
                    WHEN %s THEN %s
                    ELSE email_verification_expires_at
                END
            WHERE id = %s
            """,
            (
                username,
                email,
                avatar_path,
                must_verify_email,
                must_verify_email,
                code,
                must_verify_email,
                expires_at,
                user_id,
            ),
        )

        # Re-read the user so the desktop/web clients receive the authoritative
        # state after database triggers/defaults and verification changes.
        updated_user = conn.execute(
            """
            SELECT id, username, email, role, status, email_verified, avatar_path, created_at
            FROM app_users
            WHERE id = %s
            """,
            (user_id,),
        ).fetchone()

    # Sending email is outside the database transaction: the profile update is
    # kept even if SMTP fails, and the user receives a clear message.
    if must_verify_email and code:
        try:
            EmailService().send_verification_code(email, username, code)
            message = "Profile updated. A verification code was sent to the new email address."
        except Exception as exc:
            message = (
                "Profile updated, but the verification email could not be sent.\n\n"
                f"Error: {exc}"
            )
    else:
        message = "Profile updated successfully."

    return {
        "ok": True,
        "message": message,
        "user": user_to_public_dict(updated_user),
    }


app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(update_router)
