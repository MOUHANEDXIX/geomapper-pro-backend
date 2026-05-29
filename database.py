"""Database connection and schema bootstrap for the account backend."""

from __future__ import annotations

import os
import re
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


def _version_parts(value: str | None) -> tuple[int, ...]:
    """Return numeric parts for a simple release-version comparison."""

    if not value:
        return ()
    return tuple(int(part) for part in re.findall(r"\d+", str(value))[:4])


def _is_newer_version(latest: str | None, current: str | None) -> bool:
    """Return True when latest is newer than current."""

    latest_parts = _version_parts(latest)
    current_parts = _version_parts(current)
    width = max(len(latest_parts), len(current_parts), 1)
    latest_parts += (0,) * (width - len(latest_parts))
    current_parts += (0,) * (width - len(current_parts))
    return latest_parts > current_parts


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
    """Create backend tables if they do not already exist."""
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
                initial_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
                avatar_path TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.execute(
            """
            ALTER TABLE app_users
            ADD COLUMN IF NOT EXISTS initial_email_verified BOOLEAN NOT NULL DEFAULT FALSE
            """
        )
        conn.execute(
            """
            UPDATE app_users
            SET initial_email_verified = TRUE
            WHERE role = 'admin'
               OR email_verified = TRUE
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_releases (
                id BIGSERIAL PRIMARY KEY,
                channel TEXT NOT NULL DEFAULT 'stable',
                version TEXT NOT NULL,
                min_supported_version TEXT,
                download_url TEXT NOT NULL,
                release_notes TEXT NOT NULL DEFAULT '',
                sha256 TEXT,
                required BOOLEAN NOT NULL DEFAULT FALSE,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS app_releases_one_active_channel
            ON app_releases (channel)
            WHERE is_active
            """
        )

        release_channel = os.getenv("APP_RELEASE_CHANNEL", "stable").strip().lower() or "stable"
        release_version = os.getenv("APP_LATEST_VERSION", "1.1.1").strip() or "1.1.1"
        release_min_supported = os.getenv("APP_MIN_SUPPORTED_VERSION", "1.1.1").strip() or "1.1.1"
        default_download_url = os.getenv(
            "GEOMAPPER_DOWNLOAD_URL",
            "https://github.com/MOUHANEDXIX/geomapper-pro-downloads/releases/latest/download/GeoMapperProSetup.exe",
        ).strip()
        release_download_url = os.getenv("APP_DOWNLOAD_URL", default_download_url).strip() or default_download_url
        release_notes = os.getenv(
            "APP_RELEASE_NOTES",
            "GeoMapper Pro 1.1.1: fixes vector drag-and-drop format validation, switches releases to a Windows installer, and enforces required update prompts for signed-in sessions.",
        )
        release_sha256 = os.getenv(
            "APP_RELEASE_SHA256",
            "",
        ).strip() or None
        release_required = os.getenv("APP_UPDATE_REQUIRED", "false").strip().lower() in {"1", "true", "yes"}

        active_release = conn.execute(
            """
            SELECT id, version
            FROM app_releases
            WHERE channel = %s
              AND is_active = TRUE
            LIMIT 1
            """,
            (release_channel,),
        ).fetchone()

        should_publish_release = not active_release or _is_newer_version(release_version, active_release.get("version"))
        if should_publish_release:
            if active_release:
                conn.execute(
                    """
                    UPDATE app_releases
                    SET is_active = FALSE
                    WHERE id = %s
                    """,
                    (active_release["id"],),
                )
            conn.execute(
                """
                INSERT INTO app_releases (
                    channel,
                    version,
                    min_supported_version,
                    download_url,
                    release_notes,
                    sha256,
                    required,
                    is_active
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE)
                """,
                (
                    release_channel,
                    release_version,
                    release_min_supported,
                    release_download_url,
                    release_notes,
                    release_sha256,
                    release_required,
                ),
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
                    initial_email_verified = TRUE,
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
                email_verified,
                initial_email_verified
            )
            VALUES (%s, %s, %s, 'admin', 'paid', TRUE, TRUE)
            """,
            (username, email, password_hash),
        )


def cleanup_expired_unverified_users() -> int:
    """Delete newly-created accounts that missed their verification window."""
    with get_db() as conn:
        rows = conn.execute(
            """
            DELETE FROM app_users
            WHERE role <> 'admin'
              AND email_verified = FALSE
              AND initial_email_verified = FALSE
              AND email_verification_expires_at IS NOT NULL
              AND email_verification_expires_at <= NOW()
            RETURNING id
            """
        ).fetchall()

    return len(rows)
