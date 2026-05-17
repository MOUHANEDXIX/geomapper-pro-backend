"""SMTP email helper for account verification messages."""

from __future__ import annotations

import json
import os
import smtplib
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().with_name(".env"), override=True)


class EmailService:
    """Read SMTP settings from `.env` and send verification emails."""

    def __init__(self):
        """Load SMTP connection settings from environment variables."""
        self.smtp_host = os.getenv("APP_SMTP_HOST")
        self.smtp_port = int(os.getenv("APP_SMTP_PORT", "465"))
        self.smtp_email = os.getenv("APP_SMTP_EMAIL")
        self.smtp_password = os.getenv("APP_SMTP_PASSWORD", "").replace(" ", "")
        self.from_name = os.getenv("APP_SMTP_FROM_NAME", "GeoMapper Pro")
        self.from_email = os.getenv("APP_EMAIL_FROM_EMAIL") or self.smtp_email
        self.brevo_api_key = os.getenv("BREVO_API_KEY", "").strip()

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

        if self.brevo_api_key:
            self._send_with_brevo(to_email, username, subject, text)
            return

        self._send_with_smtp(to_email, subject, text)

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
        msg["From"] = formataddr((self.from_name, self.smtp_email))
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
