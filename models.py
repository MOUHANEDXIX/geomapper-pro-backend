"""Pydantic request and response models for the account API."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    """Payload for creating a new user account."""

    username: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=4, max_length=128)


class LoginRequest(BaseModel):
    """Payload for username/email plus password sign-in."""

    login: str = Field(min_length=1)
    password: str = Field(min_length=1)


class VerifyEmailRequest(BaseModel):
    """Payload for submitting an email verification code."""

    email: EmailStr
    code: str = Field(min_length=1, max_length=20)


class ResendCodeRequest(BaseModel):
    """Payload for requesting a fresh verification code."""

    email: EmailStr


class StatusUpdateRequest(BaseModel):
    """Payload for admin payment/access status changes."""

    status: str


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
