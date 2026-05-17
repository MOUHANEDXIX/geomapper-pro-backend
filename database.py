"""Database connection and schema bootstrap for the account backend."""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote, unquote

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row

load_dotenv(Path(__file__).resolve().with_name(".env"), override=True)

DATABASE_URL = os.getenv("DATABASE_URL")


if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing from .env")


def normalize_database_url(database_url: str) -> str:
    """
    Percent-encode the password part of a PostgreSQL URL.

    Supabase passwords often contain characters like @, [ or ]. Those are valid
    password characters, but they must be encoded inside a URL or psycopg can
    misread part of the password as the hostname.
    """
    database_url = database_url.strip().strip('"').strip("'")

    if "://" not in database_url or "@" not in database_url:
        return database_url

    scheme, rest = database_url.split("://", 1)
    userinfo, hostinfo = rest.rsplit("@", 1)

    if ":" not in userinfo:
        return database_url

    username, password = userinfo.split(":", 1)
    password = unquote(password)

    # Supabase examples show the password as [YOUR-PASSWORD]. If those
    # placeholder brackets are copied into .env, authentication will fail.
    if password.startswith("[") and password.endswith("]") and len(password) > 2:
        password = password[1:-1]

    encoded_password = quote(password, safe="")

    return f"{scheme}://{username}:{encoded_password}@{hostinfo}"


DATABASE_URL = normalize_database_url(DATABASE_URL)


@contextmanager
def get_db():
    """Yield a PostgreSQL connection and commit/rollback automatically."""
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create the account table if it does not already exist."""
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_users (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                status TEXT NOT NULL DEFAULT 'awaiting_payment',
                email_verified BOOLEAN NOT NULL DEFAULT FALSE,
                email_verification_code TEXT,
                email_verification_expires_at TIMESTAMPTZ,
                avatar_path TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )


def init_default_admin():
    """Create or repair the configured administrator account."""
    from security import hash_password

    init_db()

    username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@geotun.local")
    password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")

    password_hash = hash_password(password)

    with get_db() as conn:
        # If the admin already exists by username/email, force it back into a
        # usable administrator state instead of creating a duplicate account.
        existing = conn.execute(
            """
            SELECT id FROM app_users
            WHERE LOWER(username) = LOWER(%s)
               OR LOWER(email) = LOWER(%s)
            """,
            (username, email),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE app_users
                SET role = 'admin',
                    status = 'paid',
                    email_verified = TRUE,
                    email_verification_code = NULL,
                    email_verification_expires_at = NULL
                WHERE id = %s
                """,
                (existing["id"],),
            )
            return

        # First-run bootstrap: insert the default admin with paid/full access.
        conn.execute(
            """
            INSERT INTO app_users (
                username,
                email,
                password_hash,
                role,
                status,
                email_verified
            )
            VALUES (%s, %s, %s, 'admin', 'paid', TRUE)
            """,
            (username, email, password_hash),
        )
