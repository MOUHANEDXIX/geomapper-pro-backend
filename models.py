"""Pydantic request and response models for the account API."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    """Payload for creating a new user account."""

    username: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    """Payload for username/email plus password sign-in."""

    login: str = Field(min_length=1)
    password: str = Field(min_length=1)
    device_id: str | None = Field(default=None, max_length=120)
    device_name: str | None = Field(default=None, max_length=180)
    client_name: str | None = Field(default=None, max_length=80)


class VerifyEmailRequest(BaseModel):
    """Payload for submitting an email verification code."""

    email: EmailStr
    code: str = Field(min_length=1, max_length=20)


class ResendCodeRequest(BaseModel):
    """Payload for requesting a fresh verification code."""

    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    """Payload for requesting a password-reset code."""

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Payload for replacing a password after validating a reset code."""

    email: EmailStr
    code: str = Field(min_length=6, max_length=20)
    new_password: str = Field(min_length=8, max_length=128)


class ChangePasswordRequest(BaseModel):
    """Payload for an authenticated password change."""

    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class DeactivateAccountRequest(BaseModel):
    """Payload for self-service account deactivation."""

    password: str = Field(min_length=1, max_length=128)


class StatusUpdateRequest(BaseModel):
    """Payload for admin payment/access status changes."""

    status: str
    payment_plan: str | None = Field(default=None, max_length=20)


class AppReleaseUpdateRequest(BaseModel):
    """Payload for publishing the active desktop app release metadata."""

    version: str = Field(min_length=1, max_length=40)
    download_url: str = Field(min_length=1, max_length=500)
    release_notes: str = Field(default="", max_length=4000)
    channel: str = Field(default="stable", min_length=1, max_length=40)
    min_supported_version: str | None = Field(default=None, max_length=40)
    sha256: str | None = Field(default=None, max_length=128)
    signature: str | None = Field(default=None, max_length=512)
    signature_algorithm: str | None = Field(default="ed25519-sha256", max_length=40)
    release_label: str | None = Field(default=None, max_length=100)
    installer_filename: str | None = Field(default=None, max_length=180)
    installer_size_bytes: int | None = Field(default=None, ge=0)
    required: bool = False

    @field_validator("channel")
    @classmethod
    def normalize_channel(cls, value: str) -> str:
        """Keep release channels URL-safe and predictable."""
        channel = value.strip().lower()
        if not channel.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Release channel must be alphanumeric.")
        return channel


class ProfileUpdateRequest(BaseModel):
    """Payload for profile edits from the desktop app or website."""

    username: str = Field(min_length=2, max_length=80)
    email: EmailStr
    avatar_path: str | None = Field(default=None, max_length=350_000)

    @field_validator("avatar_path")
    @classmethod
    def validate_avatar_path(cls, value: str | None) -> str | None:
        """Accept data-image avatars and old local path values."""
        if not value:
            return None

        if value.startswith("data:image/"):
            header, separator, payload = value.partition(",")
            if not separator or ";base64" not in header or not payload:
                raise ValueError("Avatar image data is invalid.")
            return value

        # Legacy desktop versions stored a local image path here.
        return value


class PlanRequest(BaseModel):
    """Payload for requesting manual activation of a paid plan."""

    plan: str = Field(min_length=1, max_length=20)

    @field_validator("plan")
    @classmethod
    def validate_plan(cls, value: str) -> str:
        """Allow only customer-facing paid plans."""
        plan = value.strip().lower()
        if plan not in {"plus", "pro"}:
            raise ValueError("Choose Plus or Pro.")
        return plan


class PaymentRequestCreate(BaseModel):
    """Payload for creating a manual bank-transfer payment request."""

    plan_code: str = Field(min_length=1, max_length=20)
    proof_url: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=1000)

    @field_validator("plan_code")
    @classmethod
    def validate_plan_code(cls, value: str) -> str:
        plan = value.strip().lower()
        if plan not in {"plus", "pro"}:
            raise ValueError("Choose Plus or Pro.")
        return plan


class PaymentRejectRequest(BaseModel):
    """Payload for rejecting a pending/manual payment."""

    notes: str = Field(default="", max_length=1000)


class PaymentNoteRequest(BaseModel):
    """Payload for changing an admin payment note."""

    notes: str = Field(default="", max_length=1000)


class AdminSubscriptionRenewRequest(BaseModel):
    """Payload for creating/renewing a subscription from the admin panel."""

    plan_code: str = Field(min_length=1, max_length=20)
    notes: str | None = Field(default=None, max_length=1000)

    @field_validator("plan_code")
    @classmethod
    def validate_plan_code(cls, value: str) -> str:
        plan = value.strip().lower()
        if plan not in {"plus", "pro"}:
            raise ValueError("Choose Plus or Pro.")
        return plan


class SupportRequest(BaseModel):
    """Payload for the public support form."""

    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    subject: str = Field(min_length=3, max_length=180)
    category: str = Field(min_length=2, max_length=40)
    message: str = Field(min_length=10, max_length=5000)

    @field_validator("category")
    @classmethod
    def validate_category(cls, value: str) -> str:
        """Keep support categorization predictable for the admin team."""
        category = value.strip().lower().replace(" ", "_")
        allowed = {
            "bug_report",
            "account_problem",
            "payment_request",
            "installation_problem",
            "technical_support",
            "other",
        }
        if category not in allowed:
            raise ValueError("Choose a valid support category.")
        return category


class AnalyticsEventRequest(BaseModel):
    """Minimal privacy-friendly anonymous website event."""

    event_name: str = Field(min_length=2, max_length=60)
    session_id: str | None = Field(default=None, max_length=100)
    page: str | None = Field(default=None, max_length=180)
    metadata: dict | None = None

    @field_validator("event_name")
    @classmethod
    def validate_event_name(cls, value: str) -> str:
        """Accept only the documented anonymous product events."""
        event_name = value.strip().lower()
        allowed = {
            "homepage_visit",
            "pricing_viewed",
            "download_clicked",
            "signup_started",
            "signup_completed",
            "demo_opened",
            "support_submitted",
            "plan_selected",
            "changelog_viewed",
        }
        if event_name not in allowed:
            raise ValueError("Unsupported analytics event.")
        return event_name


class ApiResponse(BaseModel):
    """Common success/message response."""

    ok: bool
    message: str


class AuthResponse(BaseModel):
    """Login response with optional token and public user data."""

    ok: bool
    message: str
    token: str | None = None
    user: dict | None = None
