"""Authentication, verification, and password-recovery routes."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request

from access_policy import active_plan_code
from database import cleanup_expired_unverified_users, get_db
from email_service import EmailService
from models import (
    ApiResponse,
    AuthResponse,
    ForgotPasswordRequest,
    LoginRequest,
    RegisterRequest,
    ResendCodeRequest,
    ResetPasswordRequest,
    VerifyEmailRequest,
)
from rate_limit import enforce_rate_limit
from security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["Auth"])
logger = logging.getLogger(__name__)

STATUS_AWAITING = "awaiting_payment"
STATUS_PAID = "paid"
STATUS_UNPAID = "unpaid"
ACCOUNT_ACTIVE = "active"
RESET_MESSAGE = "If this email exists, a password reset message has been sent."


def generate_code() -> tuple[str, datetime]:
    """Create a short-lived six-digit email code."""
    code = str(secrets.randbelow(900_000) + 100_000)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    return code, expires_at


def user_to_public_dict(user: dict) -> dict:
    """Convert a database row into the safe account shape returned to clients."""
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "status": user["status"],
        "account_state": user.get("account_state") or ACCOUNT_ACTIVE,
        "payment_plan": user.get("payment_plan") or "free",
        "requested_plan": user.get("requested_plan"),
        "active_plan": active_plan_code(user),
        "email_verified": bool(user["email_verified"]),
        "avatar_path": user.get("avatar_path"),
        "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
    }


def _normalized_timestamp(value: datetime | None) -> datetime | None:
    """Return a timezone-aware timestamp for database-driver compatibility."""
    if value and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


@router.post("/register", response_model=ApiResponse)
def register_user(payload: RegisterRequest, request: Request):
    """Create a normal user account and send an email verification code."""
    cleanup_expired_unverified_users()
    username = payload.username.strip()
    email = str(payload.email).strip().lower()
    password = payload.password.strip()
    enforce_rate_limit(request, "signup", email)
    code, expires_at = generate_code()

    try:
        with get_db() as conn:
            existing = conn.execute(
                """
                SELECT id FROM app_users
                WHERE LOWER(username) = LOWER(%s)
                   OR LOWER(email) = LOWER(%s)
                """,
                (username, email),
            ).fetchone()

            if existing:
                return ApiResponse(ok=False, message="Username or email is already in use.")

            conn.execute(
                """
                INSERT INTO app_users (
                    username,
                    email,
                    password_hash,
                    role,
                    status,
                    account_state,
                    payment_plan,
                    email_verified,
                    email_verification_code,
                    email_verification_expires_at
                )
                VALUES (%s, %s, %s, 'user', %s, 'active', 'free', FALSE, %s, %s)
                """,
                (username, email, hash_password(password), STATUS_AWAITING, code, expires_at),
            )
    except Exception:
        logger.exception("Account registration failed")
        raise HTTPException(status_code=500, detail="Account creation is temporarily unavailable. Please try again later.")

    try:
        EmailService().send_verification_code(email, username, code)
    except Exception:
        logger.exception("Verification email delivery failed for new account")
        return ApiResponse(
            ok=True,
            message=(
                "Account created, but the verification email could not be sent. "
                "Please use 'Resend code' shortly or contact support."
            ),
        )

    return ApiResponse(
        ok=True,
        message=(
            "Account created successfully. A verification code was sent to your email.\n"
            "After verification, Raster and Vector access will be enabled after payment validation."
        ),
    )


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest, request: Request):
    """Authenticate a user/admin and return a JWT plus public profile."""
    cleanup_expired_unverified_users()
    login_value = payload.login.strip()
    password = payload.password.strip()
    enforce_rate_limit(request, "login", login_value)

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

    if not user or not verify_password(password, user["password_hash"]):
        return AuthResponse(ok=False, message="Incorrect login or password.")

    if user.get("account_state", ACCOUNT_ACTIVE) != ACCOUNT_ACTIVE:
        return AuthResponse(ok=False, message="This account is unavailable. Contact support for help.")

    if user["role"] != "admin" and not bool(user["email_verified"]):
        return AuthResponse(ok=False, message="Verify your email before signing in.")

    token = create_access_token({"sub": str(user["id"]), "role": user["role"]})
    public_user = user_to_public_dict(user)

    if user["role"] == "admin":
        message = "Administrator sign-in successful."
    elif user["status"] == STATUS_PAID:
        message = "Sign-in successful. Full access is enabled."
    elif user["status"] == STATUS_UNPAID:
        message = "Sign-in successful. Your account is unpaid, so Raster and Vector remain locked."
    else:
        message = "Sign-in successful. Your account is awaiting payment validation."

    return AuthResponse(ok=True, message=message, token=token, user=public_user)


@router.post("/verify-email", response_model=ApiResponse)
def verify_email(payload: VerifyEmailRequest, request: Request):
    """Validate an email verification code and mark the account verified."""
    cleanup_expired_unverified_users()
    email = str(payload.email).strip().lower()
    code = payload.code.strip()
    enforce_rate_limit(request, "verify_email", email)

    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, email_verification_code, email_verification_expires_at
            FROM app_users
            WHERE LOWER(email) = LOWER(%s)
              AND account_state = 'active'
            """,
            (email,),
        ).fetchone()

        if not user:
            return ApiResponse(ok=False, message="No account was found for this email address.")

        saved_code = user["email_verification_code"]
        expires_at = _normalized_timestamp(user["email_verification_expires_at"])
        if not saved_code or not expires_at:
            return ApiResponse(ok=False, message="No active code. Click 'Resend code'.")
        if datetime.now(timezone.utc) > expires_at:
            return ApiResponse(ok=False, message="The code has expired. Click 'Resend code'.")
        if code != saved_code:
            return ApiResponse(ok=False, message="Incorrect verification code.")

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
def resend_code(payload: ResendCodeRequest, request: Request):
    """Generate and email a fresh verification code for an unverified user."""
    cleanup_expired_unverified_users()
    email = str(payload.email).strip().lower()
    enforce_rate_limit(request, "resend_code", email)
    code, expires_at = generate_code()

    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, username, email_verified
            FROM app_users
            WHERE LOWER(email) = LOWER(%s)
              AND account_state = 'active'
            """,
            (email,),
        ).fetchone()

        if not user:
            return ApiResponse(ok=False, message="No account was found for this email address.")
        if bool(user["email_verified"]):
            return ApiResponse(ok=False, message="This email address is already verified.")

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
    except Exception:
        logger.exception("Verification resend email delivery failed")
        return ApiResponse(ok=False, message="Unable to send the verification email right now. Please try again later.")

    return ApiResponse(ok=True, message="A new verification code was sent to your email.")


@router.post("/forgot-password", response_model=ApiResponse)
def forgot_password(payload: ForgotPasswordRequest, request: Request):
    """Send a reset code without revealing whether the account exists."""
    email = str(payload.email).strip().lower()
    enforce_rate_limit(request, "forgot_password", email)
    code, expires_at = generate_code()

    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, username
            FROM app_users
            WHERE LOWER(email) = LOWER(%s)
              AND account_state = 'active'
            """,
            (email,),
        ).fetchone()
        if user:
            conn.execute(
                """
                UPDATE app_users
                SET password_reset_code = %s,
                    password_reset_expires_at = %s
                WHERE id = %s
                """,
                (code, expires_at, user["id"]),
            )

    if user:
        try:
            EmailService().send_password_reset_code(email, user["username"], code)
        except Exception:
            logger.exception("Password-reset email delivery failed")

    return ApiResponse(ok=True, message=RESET_MESSAGE)


@router.post("/reset-password", response_model=ApiResponse)
def reset_password(payload: ResetPasswordRequest, request: Request):
    """Replace a password after validating its short-lived reset code."""
    email = str(payload.email).strip().lower()
    code = payload.code.strip()
    enforce_rate_limit(request, "reset_password", email)

    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, password_reset_code, password_reset_expires_at
            FROM app_users
            WHERE LOWER(email) = LOWER(%s)
              AND account_state = 'active'
            """,
            (email,),
        ).fetchone()

        if not user:
            return ApiResponse(ok=False, message="The reset code is invalid or expired.")

        expires_at = _normalized_timestamp(user["password_reset_expires_at"])
        if (
            not user["password_reset_code"]
            or not expires_at
            or datetime.now(timezone.utc) > expires_at
            or not secrets.compare_digest(code, user["password_reset_code"])
        ):
            return ApiResponse(ok=False, message="The reset code is invalid or expired.")

        conn.execute(
            """
            UPDATE app_users
            SET password_hash = %s,
                password_reset_code = NULL,
                password_reset_expires_at = NULL
            WHERE id = %s
            """,
            (hash_password(payload.new_password.strip()), user["id"]),
        )

    return ApiResponse(ok=True, message="Password updated successfully. You can now sign in.")
