"""Authentication and email-verification routes for GeoMapper Pro."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException

from database import cleanup_expired_unverified_users, get_db
from email_service import EmailService
from models import (
    ApiResponse,
    AuthResponse,
    LoginRequest,
    RegisterRequest,
    ResendCodeRequest,
    VerifyEmailRequest,
)
from security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["Auth"])

STATUS_AWAITING = "awaiting_payment"
STATUS_PAID = "paid"
STATUS_UNPAID = "unpaid"


def generate_code() -> tuple[str, datetime]:
    """Create a short-lived six-digit email verification code."""
    code = str(random.randint(100000, 999999))
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    return code, expires_at


def user_to_public_dict(user: dict) -> dict:
    """Convert a database row into the account shape returned to clients."""
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


@router.post("/register", response_model=ApiResponse)
def register_user(payload: RegisterRequest):
    """Create a normal user account and send an email verification code."""
    cleanup_expired_unverified_users()
    username = payload.username.strip()
    email = str(payload.email).strip().lower()
    password = payload.password.strip()

    code, expires_at = generate_code()

    try:
        with get_db() as conn:
            # Reject duplicate usernames/emails before inserting the account.
            existing = conn.execute(
                """
                SELECT id FROM app_users
                WHERE LOWER(username) = LOWER(%s)
                   OR LOWER(email) = LOWER(%s)
                """,
                (username, email),
            ).fetchone()

            if existing:
                return ApiResponse(
                    ok=False,
                    message="Username or email is already in use.",
                )

            # New users start locked to paid modules until email and payment
            # validation complete.
            conn.execute(
                """
                INSERT INTO app_users (
                    username,
                    email,
                    password_hash,
                    role,
                    status,
                    email_verified,
                    email_verification_code,
                    email_verification_expires_at
                )
                VALUES (%s, %s, %s, 'user', %s, FALSE, %s, %s)
                """,
                (
                    username,
                    email,
                    hash_password(password),
                    STATUS_AWAITING,
                    code,
                    expires_at,
                ),
            )

        # The account remains created if SMTP fails, but the caller gets clear
        # instructions so verification can be retried after configuration fixes.
        try:
            EmailService().send_verification_code(email, username, code)
        except Exception as exc:
            return ApiResponse(
                ok=True,
                message=(
                    "Account created, but the verification email could not be sent.\n\n"
                    f"Error: {exc}\n\n"
                    "After SMTP is corrected, click 'Verify email' and then 'Resend code'."
                ),
            )

        return ApiResponse(
            ok=True,
            message=(
                "Account created successfully. A verification code was sent to your email.\n"
                "After verification, Raster and Vector access will be enabled after payment validation."
            ),
        )

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    """Authenticate a user/admin and return a JWT plus public profile."""
    cleanup_expired_unverified_users()
    login_value = payload.login.strip()
    password = payload.password.strip()

    # Accept either username or email in the same login field.
    with get_db() as conn:
        user = conn.execute(
            """
            SELECT *
            FROM app_users
            WHERE LOWER(username) = LOWER(%s)
               OR LOWER(email) = LOWER(%s)
            """,
            (login_value, login_value),
        ).fetchone()

    if not user:
        return AuthResponse(ok=False, message="Account not found.")

    if not verify_password(password, user["password_hash"]):
        return AuthResponse(ok=False, message="Incorrect password.")

    # Admins bypass email verification so the default admin can bootstrap the
    # system even before SMTP is configured.
    if user["role"] != "admin" and not bool(user["email_verified"]):
        return AuthResponse(ok=False, message="Verify your email before signing in.")

    token = create_access_token(
        {
            "sub": str(user["id"]),
            "role": user["role"],
        }
    )

    public_user = user_to_public_dict(user)

    # Return a message that explains the access level the user just received.
    if user["role"] == "admin":
        msg = "Administrator sign-in successful."
    elif user["status"] == STATUS_PAID:
        msg = "Sign-in successful. Full access is enabled."
    elif user["status"] == STATUS_UNPAID:
        msg = "Sign-in successful. Your account is unpaid, so Raster and Vector remain locked."
    else:
        msg = "Sign-in successful. Your account is awaiting payment validation."

    return AuthResponse(
        ok=True,
        message=msg,
        token=token,
        user=public_user,
    )


@router.post("/verify-email", response_model=ApiResponse)
def verify_email(payload: VerifyEmailRequest):
    """Validate an email verification code and mark the account verified."""
    cleanup_expired_unverified_users()
    email = str(payload.email).strip().lower()
    code = payload.code.strip()

    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, email_verification_code, email_verification_expires_at
            FROM app_users
            WHERE LOWER(email) = LOWER(%s)
            """,
            (email,),
        ).fetchone()

        if not user:
            return ApiResponse(ok=False, message="No account was found for this email address.")

        saved_code = user["email_verification_code"]
        expires_at = user["email_verification_expires_at"]

        if not saved_code or not expires_at:
            return ApiResponse(ok=False, message="No active code. Click 'Resend code'.")

        now = datetime.now(timezone.utc)

        # Normalize old/driver-returned naive timestamps before comparing with
        # the timezone-aware current time.
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now > expires_at:
            return ApiResponse(ok=False, message="The code has expired. Click 'Resend code'.")

        if code != saved_code:
            return ApiResponse(ok=False, message="Incorrect verification code.")

        # Clear the code after successful verification so it cannot be reused.
        conn.execute(
            """
            UPDATE app_users
            SET email_verified = TRUE,
                initial_email_verified = TRUE,
                email_verification_code = NULL,
                email_verification_expires_at = NULL
            WHERE id = %s
            """,
            (user["id"],),
        )

    return ApiResponse(ok=True, message="Email verified successfully. You can now sign in.")


@router.post("/resend-code", response_model=ApiResponse)
def resend_code(payload: ResendCodeRequest):
    """Generate and email a fresh verification code for an unverified user."""
    cleanup_expired_unverified_users()
    email = str(payload.email).strip().lower()
    code, expires_at = generate_code()

    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, username, email_verified
            FROM app_users
            WHERE LOWER(email) = LOWER(%s)
            """,
            (email,),
        ).fetchone()

        if not user:
            return ApiResponse(ok=False, message="No account was found for this email address.")

        if bool(user["email_verified"]):
            return ApiResponse(ok=False, message="This email address is already verified.")

        # Store the new code before sending email so a successful message always
        # corresponds to the current database value.
        conn.execute(
            """
            UPDATE app_users
            SET email_verification_code = %s,
                email_verification_expires_at = %s
            WHERE id = %s
            """,
            (code, expires_at, user["id"]),
        )

    try:
        EmailService().send_verification_code(email, user["username"], code)
    except Exception as exc:
        return ApiResponse(
            ok=False,
            message=f"Unable to send the verification email: {exc}",
        )

    return ApiResponse(ok=True, message="A new verification code was sent to your email.")
