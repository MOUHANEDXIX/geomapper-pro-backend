"""SMTP email helper for account verification messages."""

from __future__ import annotations

import json
import logging
import os
import smtplib
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().with_name(".env"), override=True, encoding="utf-8-sig")
logger = logging.getLogger(__name__)


class EmailService:
    """Read SMTP settings from `.env` and send verification emails."""

    def __init__(self):
        """Load SMTP connection settings from environment variables."""
        self.smtp_host = _first_env("APP_SMTP_HOST", "SMTP_HOST")
        self.smtp_port = _env_int("APP_SMTP_PORT", "SMTP_PORT", default=465)
        self.smtp_email = _first_env("APP_SMTP_EMAIL", "SMTP_USER")
        self.smtp_password = (_first_env("APP_SMTP_PASSWORD", "SMTP_PASS") or "").replace(" ", "")
        self.from_name = _first_env("APP_SMTP_FROM_NAME", "SMTP_FROM_NAME") or "GeoMapper Pro"
        self.from_email = _first_env("APP_EMAIL_FROM_EMAIL", "APP_SMTP_FROM_EMAIL", "APP_SMTP_EMAIL", "SMTP_USER")
        self.brevo_api_key = _first_env("BREVO_API_KEY", "APP_BREVO_API_KEY", "SENDINBLUE_API_KEY") or ""
        self.support_email = (_first_env("SUPPORT_EMAIL") or "progeomapper@gmail.com").strip()
        self.password_reset_url = os.getenv(
            "PASSWORD_RESET_URL",
            f"{os.getenv('FRONTEND_URL', 'https://geomapperpro.pages.dev').rstrip('/')}/#account",
        ).strip()

    def send_verification_code(self, to_email: str, username: str, code: str) -> None:
        """Send a six-digit verification code to one account email address."""
        subject = "GeoMapper Pro - Verification code"
        text = (
            f"Hello {username},\n\n"
            f"Your verification code is: {code}\n\n"
            "It expires in 10 minutes.\n\n"
            "Regards,\n"
            "GeoMapper Pro\n"
        )

        self._send_text(to_email, username, subject, text)

    def send_password_reset_code(self, to_email: str, username: str, code: str) -> None:
        """Send a short-lived password-reset code."""
        subject = "GeoMapper Pro - Password reset code"
        text = (
            f"Hello {username},\n\n"
            f"Your password reset code is: {code}\n\n"
            "It expires in 10 minutes. If you did not request this change, "
            "you can ignore this message.\n\n"
            f"Open GeoMapper Pro password recovery: {self.password_reset_url}\n\n"
            "Regards,\n"
            "GeoMapper Pro\n"
        )
        self._send_text(to_email, username, subject, text)

    def send_support_notification(
        self,
        name: str,
        email: str,
        category: str,
        subject: str,
        message: str,
    ) -> None:
        """Notify the support inbox after a website support request is stored."""
        text = (
            "A new GeoMapper Pro support request was submitted.\n\n"
            f"Name: {name}\n"
            f"Email: {email}\n"
            f"Category: {category}\n"
            f"Subject: {subject}\n\n"
            f"{message}\n"
        )
        self._send_text(self.support_email, "GeoMapper Pro Support", f"[GeoMapper Pro] {subject}", text)

    def _send_text(self, to_email: str, recipient_name: str, subject: str, text: str) -> None:
        """Send one plain-text transactional email through the configured provider."""
        if self.brevo_api_key:
            try:
                self._send_with_brevo(to_email, recipient_name, subject, text)
                return
            except Exception:
                if not self._has_smtp_config():
                    raise
                logger.exception("Brevo delivery failed; falling back to SMTP.")
        self._send_with_smtp(to_email, subject, text)

    def _has_smtp_config(self) -> bool:
        """Return True when enough SMTP settings exist for fallback delivery."""

        return bool(self.smtp_host and self.smtp_email and self.smtp_password)

    def _send_with_brevo(
        self,
        to_email: str,
        username: str,
        subject: str,
        text: str,
    ) -> None:
        """Send mail through Brevo's HTTPS API, which works on SMTP-blocked hosts."""
        if not self.from_email:
            raise RuntimeError("APP_EMAIL_FROM_EMAIL or APP_SMTP_EMAIL is missing.")

        payload = {
            "sender": {
                "name": self.from_name,
                "email": self.from_email,
            },
            "to": [
                {
                    "email": to_email,
                    "name": username,
                }
            ],
            "subject": subject,
            "textContent": text,
        }

        request = urllib.request.Request(
            "https://api.brevo.com/v3/smtp/email",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "api-key": self.brevo_api_key,
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status >= 400:
                    raise RuntimeError(f"Brevo API returned HTTP {response.status}.")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Brevo API returned HTTP {exc.code}: {body}") from exc

    def _send_with_smtp(self, to_email: str, subject: str, text: str) -> None:
        """Send mail through a traditional SMTP server."""
        if not self.smtp_host:
            raise RuntimeError("APP_SMTP_HOST is missing.")

        if not self.smtp_email:
            raise RuntimeError("APP_SMTP_EMAIL is missing.")

        if not self.smtp_password:
            raise RuntimeError("APP_SMTP_PASSWORD is missing.")

        # Build a plain-text message so every email client can display it.
        msg = EmailMessage()
        msg["From"] = formataddr((self.from_name, self.from_email or self.smtp_email))
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.set_content(text)

        # Port 465 expects SMTP over SSL from the first byte; other ports use
        # STARTTLS after connecting.
        if self.smtp_port == 465:
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=20) as server:
                server.login(self.smtp_email, self.smtp_password)
                server.send_message(msg)
            return

        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=20) as server:
            server.starttls()
            server.login(self.smtp_email, self.smtp_password)
            server.send_message(msg)


def _first_env(*names: str) -> str | None:
    """Return the first non-empty environment value from a list of names."""

    for name in names:
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    return None


def _env_int(*names: str, default: int) -> int:
    """Read an integer environment value with a safe fallback."""

    value = _first_env(*names)
    if not value:
        return default

    try:
        return int(value)
    except ValueError:
        return default
