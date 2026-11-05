"""Password hashing and JWT helpers for the account backend."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
import jwt
from jwt import InvalidTokenError

load_dotenv(Path(__file__).resolve().with_name(".env"), override=True, encoding="utf-8-sig")

logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv("JWT_SECRET", "change_me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

PBKDF2_ITERATIONS = 260_000
EXACT_PASSWORD_PREFIX = "pbkdf2_sha256_exact"


def _is_production_environment() -> bool:
    """Return True when the backend is running in a hosted/production context."""
    env_names = ("APP_ENV", "ENV", "ENVIRONMENT", "PYTHON_ENV")
    if any(os.getenv(name, "").strip().lower() in {"prod", "production"} for name in env_names):
        return True
    return os.getenv("RENDER", "").strip().lower() in {"1", "true", "yes"}


if _is_production_environment() and JWT_SECRET == "change_me":
    raise RuntimeError(
        "JWT_SECRET is not configured. Set the JWT_SECRET environment variable "
        "before starting the backend in production; a missing secret would "
        "silently invalidate every user session on each restart."
    )


def hash_password(password: str) -> str:
    """
    Hash the exact password string without normalizing its whitespace.

    Format:
    pbkdf2_sha256_exact$iterations$salt$hash
    """
    if not isinstance(password, str) or not password.strip():
        raise ValueError("Password must contain a non-whitespace character.")
    salt = secrets.token_hex(16)

    # PBKDF2 is available in the Python standard library, which keeps packaged
    # builds simpler than native bcrypt dependencies.
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    ).hex()

    return f"{EXACT_PASSWORD_PREFIX}${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify exact new credentials and preserve legacy sign-in compatibility.

    Older account routes stripped passwords before hashing. Only legacy hashes
    retain that fallback; reset/change creates an explicitly exact credential.
    Exact-first also preserves administrator hashes that were never stripped.
    """
    if not password_hash or not isinstance(password, str) or not password.strip():
        return False

    is_exact = password_hash.startswith(EXACT_PASSWORD_PREFIX + "$")
    is_legacy_pbkdf2 = password_hash.startswith("pbkdf2_sha256$")
    if is_exact or is_legacy_pbkdf2:
        try:
            _, iterations, salt, expected_digest = password_hash.split("$")
            iterations = int(iterations)

            candidates = [password]
            if is_legacy_pbkdf2 and password.strip() != password:
                candidates.append(password.strip())
            for candidate in candidates:
                calculated_digest = hashlib.pbkdf2_hmac(
                    "sha256", candidate.encode("utf-8"), salt.encode("utf-8"), iterations,
                ).hex()
                if hmac.compare_digest(calculated_digest, expected_digest):
                    return True
            return False
        except Exception:
            return False

    # Compatibility with old local AuthManager SHA-256 passwords.
    if len(password_hash) == 64:
        for candidate in (password, password.strip()):
            old_digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
            if hmac.compare_digest(old_digest, password_hash):
                return True

    return False


def password_needs_rehash(password_hash: str) -> bool:
    """Return True for hashes older than the current PBKDF2 format."""
    return not (password_hash or "").startswith(EXACT_PASSWORD_PREFIX + "$")


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
    except InvalidTokenError:
        return {}
