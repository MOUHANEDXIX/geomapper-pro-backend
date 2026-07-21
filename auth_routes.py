"""Authentication, verification, and password-recovery routes."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request

from access_policy import active_plan_code, can_access_module, days_remaining, subscription_diagnostic
from admin_routes import get_current_user
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
from security import create_access_token, hash_password, password_needs_rehash, verify_password

router = APIRouter(prefix="/auth", tags=["Auth"])
logger = logging.getLogger(__name__)

STATUS_AWAITING = "awaiting_payment"
STATUS_APPROVED = "approved"
STATUS_PAID = "paid"
STATUS_UNPAID = "unpaid"
ACCOUNT_ACTIVE = "active"
RESET_MESSAGE = "If this email exists, a password reset message has been sent."
ONE_MACHINE_NOTICE = (
    " For privacy, this account can be used on one machine at a time. "
    "The previous open session was closed."
)
VERIFICATION_EMAIL_UNAVAILABLE_MESSAGE = (
    "The verification email could not be sent right now. "
    "Please try again later or contact support."
)


class VerificationEmailDeliveryError(RuntimeError):
    """Raised to roll back code changes when verification email delivery fails."""

    pass


def generate_code() -> tuple[str, datetime]:
    """Create a short-lived six-digit email code."""
    code = str(secrets.randbelow(900_000) + 100_000)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    return code, expires_at


def send_password_reset_email_background(email: str, username: str, code: str) -> None:
    """Send reset mail outside the request/response path."""

    try:
        EmailService().send_password_reset_code(email, username, code)
    except Exception:
        logger.exception("Password-reset email delivery failed")


def send_verification_email_or_raise(email: str, username: str, code: str, context: str) -> None:
    """Send a verification email, raising a route-level error on failure."""

    try:
        EmailService().send_verification_code(email, username, code)
    except Exception as exc:
        logger.exception("%s verification email delivery failed", context)
        raise VerificationEmailDeliveryError(VERIFICATION_EMAIL_UNAVAILABLE_MESSAGE) from exc


def user_to_public_dict(user: dict) -> dict:
    """Convert a database row into the safe account shape returned to clients."""
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "status": str(user["status"] or "").strip().lower() or STATUS_AWAITING,
        "account_state": user.get("account_state") or ACCOUNT_ACTIVE,
        "payment_plan": user.get("payment_plan") or "free",
        "requested_plan": user.get("requested_plan"),
        "active_plan": active_plan_code(user),
        "stored_active_plan": user.get("active_plan") or "free",
        "subscription_status": user.get("subscription_status") or "inactive",
        "subscription_started_at": _iso_timestamp(user.get("subscription_started_at")),
        "subscription_expires_at": _iso_timestamp(user.get("subscription_expires_at")),
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


def _normalized_timestamp(value: datetime | None) -> datetime | None:
    """Return a timezone-aware timestamp for database-driver compatibility."""
    if value and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _iso_timestamp(value: datetime | None) -> str | None:
    value = _normalized_timestamp(value)
    return value.isoformat() if value else None


def _session_text(value: str | None, fallback: str, limit: int) -> str:
    """Clean short device/session labels before storing them."""
    text = str(value or "").strip() or fallback
    return text[:limit]


def _create_login_session(conn, user: dict, payload: LoginRequest, request: Request) -> tuple[str, bool]:
    """Create the only active session for this account and revoke older ones."""
    user_id = int(user["id"])
    session_id = secrets.token_urlsafe(32)
    client_host = request.client.host if request.client else None
    app_version = request.headers.get("X-GeoMapper-App-Version")
    user_agent = request.headers.get("User-Agent")

    # Serialize login for this user so the partial unique index cannot race.
    conn.execute("SELECT pg_advisory_xact_lock(%s)", (user_id,))
    previous = conn.execute(
        """
        SELECT id
        FROM app_sessions
        WHERE user_id = %s
          AND revoked_at IS NULL
        LIMIT 1
        FOR UPDATE
        """,
        (user_id,),
    ).fetchone()
    conn.execute(
        """
        UPDATE app_sessions
        SET revoked_at = NOW(),
            revoked_reason = 'replaced_by_new_login'
        WHERE user_id = %s
          AND revoked_at IS NULL
        """,
        (user_id,),
    )
    conn.execute(
        """
        INSERT INTO app_sessions (
            id,
            user_id,
            device_id,
            device_name,
            client_name,
            app_version,
            client_ip,
            user_agent
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            session_id,
            user_id,
            _session_text(payload.device_id, "unknown-device", 120),
            _session_text(payload.device_name, "Unknown machine", 180),
            _session_text(payload.client_name, "GeoMapper Pro", 80),
            _session_text(app_version, "", 40) or None,
            _session_text(client_host, "", 80) or None,
            _session_text(user_agent, "", 500) or None,
        ),
    )
    return session_id, bool(previous)


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
            send_verification_email_or_raise(email, username, code, "Registration")
    except VerificationEmailDeliveryError:
        return ApiResponse(
            ok=False,
            message=(
                "Account was not created because the verification email could not be sent. "
                "Please try again later or contact support."
            ),
        )
    except Exception:
        logger.exception("Account registration failed")
        raise HTTPException(status_code=500, detail="Account creation is temporarily unavailable. Please try again later.")

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
            SELECT u.*,
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
            WHERE LOWER(u.username) = LOWER(%s)
               OR LOWER(u.email) = LOWER(%s)
            """,
            (login_value, login_value),
        ).fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        return AuthResponse(ok=False, message="Incorrect login or password.")

    # Transparently upgrade accounts still on the legacy unsalted SHA-256
    # format now that the correct password is known.
    if password_needs_rehash(user["password_hash"]):
        with get_db() as conn:
            conn.execute(
                "UPDATE app_users SET password_hash = %s WHERE id = %s",
                (hash_password(password), user["id"]),
            )

    if user.get("account_state", ACCOUNT_ACTIVE) != ACCOUNT_ACTIVE:
        return AuthResponse(ok=False, message="This account is unavailable. Contact support for help.")

    if user["role"] != "admin" and not bool(user["email_verified"]):
        return AuthResponse(ok=False, message="Verify your email before signing in.")

    with get_db() as conn:
        session_id, replaced_session = _create_login_session(conn, user, payload, request)

    token = create_access_token({"sub": str(user["id"]), "role": user["role"], "sid": session_id})
    public_user = user_to_public_dict(user)

    status = str(user.get("status") or "").strip().lower()
    plan_code = active_plan_code(user)
    if user["role"] == "admin":
        message = "Administrator sign-in successful."
    elif plan_code == "pro":
        message = "Sign-in successful. Pro access is active."
    elif plan_code == "plus":
        message = "Sign-in successful. Plus access is active."
    elif user.get("subscription_status") == "expired":
        message = "Sign-in successful. Your subscription has expired."
    elif status in {STATUS_PAID, STATUS_APPROVED}:
        message = "Sign-in successful. No active paid subscription was found."
    elif status == STATUS_UNPAID:
        message = "Sign-in successful. Your account is unpaid, so Raster and Vector remain locked."
    else:
        message = "Sign-in successful. Your account is awaiting payment validation."

    if replaced_session:
        message += ONE_MACHINE_NOTICE

    return AuthResponse(ok=True, message=message, token=token, user=public_user)


@router.post("/logout", response_model=ApiResponse)
def logout(current_user: dict = Depends(get_current_user)):
    """Revoke the current server-side session."""
    session_id = current_user.get("session_id")
    if session_id:
        with get_db() as conn:
            conn.execute(
                """
                UPDATE app_sessions
                SET revoked_at = NOW(),
                    revoked_reason = 'logout'
                WHERE id = %s
                  AND revoked_at IS NULL
                """,
                (session_id,),
            )
    return ApiResponse(ok=True, message="Signed out successfully.")


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

    try:
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
            send_verification_email_or_raise(email, user["username"], code, "Resend")
    except VerificationEmailDeliveryError:
        return ApiResponse(
            ok=False,
            message=(
                "The verification email could not be sent. "
                "Your existing code is still valid if it has not expired. Please try again later."
            ),
        )

    return ApiResponse(ok=True, message="A new verification code was sent to your email.")


@router.post("/forgot-password", response_model=ApiResponse)
def forgot_password(payload: ForgotPasswordRequest, request: Request, background_tasks: BackgroundTasks):
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
        background_tasks.add_task(send_password_reset_email_background, email, user["username"], code)

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
