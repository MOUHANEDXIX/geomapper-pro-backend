"""Password hashing and JWT helpers for the account backend."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from jose import JWTError, jwt

load_dotenv(Path(__file__).resolve().with_name(".env"), override=True)

JWT_SECRET = os.getenv("JWT_SECRET", "change_me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

PBKDF2_ITERATIONS = 260_000


def hash_password(password: str) -> str:
    """
    Stable password hashing without bcrypt/passlib.

    Format:
    pbkdf2_sha256$iterations$salt$hash
    """
    password = password or ""
    salt = secrets.token_hex(16)

    # PBKDF2 is available in the Python standard library, which keeps packaged
    # builds simpler than native bcrypt dependencies.
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    ).hex()

    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    """
    Supports:
    - new pbkdf2_sha256 hashes
    - old plain SHA-256 hashes from your first local SQLite app
    """
    if not password_hash:
        return False

    password = password or ""

    if password_hash.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt, expected_digest = password_hash.split("$")
            iterations = int(iterations)

            calculated_digest = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
            ).hex()

            return hmac.compare_digest(calculated_digest, expected_digest)
        except Exception:
            return False

    # Compatibility with old local AuthManager SHA-256 passwords.
    if len(password_hash) == 64:
        old_digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(old_digest, password_hash)

    return False


def create_access_token(data: dict, expires_minutes: Optional[int] = None) -> str:
    """Create a signed JWT with an expiry timestamp."""
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({"exp": expire})

    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode a JWT and return an empty dict when it is invalid/expired."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return {}
