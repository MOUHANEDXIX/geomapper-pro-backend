"""SMTP email helper for account verification messages."""

from __future__ import annotations

import os
import smtplib
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

    def send_verification_code(self, to_email: str, username: str, code: str) -> None:
        """Send a six-digit verification code to one account email address."""
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
        msg["Subject"] = "GeoMapper Pro - Verification code"

        msg.set_content(
            f"Hello {username},\n\n"
            f"Your verification code is: {code}\n\n"
            "It expires in 10 minutes.\n\n"
            "Regards,\n"
            "GeoMapper Pro\n"
        )

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
