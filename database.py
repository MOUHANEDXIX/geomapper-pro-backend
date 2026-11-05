"""Database connection and schema bootstrap for the account backend."""

from __future__ import annotations

import os
import atexit
import re
import logging
import threading
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote, unquote

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout, TooManyRequests

from schema_integrity import ensure_integrity_constraints
from schema_hardening import harden_backend_schema
from subscription_schema import install_subscription_rules

load_dotenv(Path(__file__).resolve().with_name(".env"), override=True, encoding="utf-8-sig")

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
logger = logging.getLogger(__name__)


def _is_production_environment() -> bool:
    """Return True when the backend is running in a hosted/production context."""
    env_names = ("APP_ENV", "ENV", "ENVIRONMENT", "PYTHON_ENV")
    if any(os.getenv(name, "").strip().lower() in {"prod", "production"} for name in env_names):
        return True
    return os.getenv("RENDER", "").strip().lower() in {"1", "true", "yes"}


class DatabaseUnavailableError(RuntimeError):
    """A bounded database operation could not complete; contains no driver details."""


class _BackendConnection(psycopg.Connection):
    @classmethod
    def connect(cls, conninfo="", **kwargs):
        # Use the public connector so deployment/test connection guards apply
        # equally to foreground work and the pool's background workers.
        try:
            return psycopg.connect(conninfo, **kwargs)
        except psycopg.Error:
            # Pool workers log reconnect failures. Never log a DSN, hostname,
            # or a driver's potentially sensitive connection error.
            raise psycopg.OperationalError("Account database connection is unavailable.") from None


_db_pool: ConnectionPool | None = None
_db_pool_lock = threading.Lock()


def _database_setting(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        raise RuntimeError(f"{name} must be an integer.") from None
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value


def _get_database_pool() -> ConnectionPool:
    """Create one lazy, bounded pool per backend process, without import-time I/O."""
    global _db_pool
    with _db_pool_lock:
        if _db_pool is None:
            pool = ConnectionPool(
                DATABASE_URL,
                connection_class=_BackendConnection,
                kwargs={
                    "row_factory": dict_row,
                    "connect_timeout": _database_setting("DB_CONNECT_TIMEOUT_SECONDS", 3, 1, 30),
                    # Supabase transaction pooling must not retain prepared
                    # statements on a different physical database session.
                    "prepare_threshold": None,
                    "application_name": "geomapper-accounts",
                },
                min_size=0,
                max_size=_database_setting("DB_POOL_MAX_SIZE", 5, 1, 32),
                max_waiting=_database_setting("DB_POOL_MAX_WAITING", 20, 1, 200),
                timeout=_database_setting("DB_POOL_TIMEOUT_SECONDS", 3, 1, 30),
                max_idle=60,
                reconnect_timeout=10,
                num_workers=2,
                name="geomapper-accounts",
                open=False,
            )
            pool.open()
            _db_pool = pool
        return _db_pool


def close_database_pool() -> None:
    """Release idle connections and worker threads after ASGI work has drained."""
    global _db_pool
    with _db_pool_lock:
        pool, _db_pool = _db_pool, None
    if pool is not None:
        pool.close(timeout=5)


# CLI proof/preflight callers can use get_db() without entering ASGI lifespan.
# Close while Python can still join worker threads, before late finalization.
atexit.register(close_database_pool)


@contextmanager
def get_db():
    """Borrow a bounded connection; atomically commit or roll back every caller."""
    try:
        with _get_database_pool().connection() as conn:
            # Transaction-local settings work with transaction poolers and
            # cannot leak to the next borrower. Values are bounded integers.
            statement_ms = _database_setting("DB_STATEMENT_TIMEOUT_MS", 10_000, 100, 120_000)
            lock_ms = _database_setting("DB_LOCK_TIMEOUT_MS", 2_000, 100, 30_000)
            idle_ms = _database_setting("DB_IDLE_TRANSACTION_TIMEOUT_MS", 60_000, 1_000, 120_000)
            conn.execute(
                f"SET LOCAL statement_timeout = '{statement_ms}ms'; "
                f"SET LOCAL lock_timeout = '{lock_ms}ms'; "
                f"SET LOCAL idle_in_transaction_session_timeout = '{idle_ms}ms'"
            )
            yield conn
    except (PoolTimeout, TooManyRequests, psycopg.OperationalError,
            psycopg.errors.QueryCanceled, psycopg.errors.LockNotAvailable):
        raise DatabaseUnavailableError("Account service is temporarily unavailable. Please try again later.") from None


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
                account_state TEXT NOT NULL DEFAULT 'active',
                payment_plan TEXT NOT NULL DEFAULT 'free',
                requested_plan TEXT,
                password_reset_code TEXT,
                password_reset_expires_at TIMESTAMPTZ,
                deactivated_at TIMESTAMPTZ,
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
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS account_state TEXT NOT NULL DEFAULT 'active'")
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS payment_plan TEXT NOT NULL DEFAULT 'free'")
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS requested_plan TEXT")
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS active_plan TEXT NOT NULL DEFAULT 'free'")
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS subscription_status TEXT NOT NULL DEFAULT 'inactive'")
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS subscription_started_at TIMESTAMPTZ")
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMPTZ")
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS last_payment_id BIGINT")
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS password_reset_code TEXT")
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMPTZ")
        conn.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMPTZ")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS plans (
                id BIGSERIAL PRIMARY KEY,
                code TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                price_tnd NUMERIC(10, 2) NOT NULL DEFAULT 0,
                duration_days INTEGER NOT NULL DEFAULT 30,
                modules JSONB NOT NULL DEFAULT '{}'::jsonb,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.execute(
            """
            INSERT INTO plans (code, name, price_tnd, duration_days, modules, active)
            VALUES
                ('free', 'Free', 0, 0, '{"coordinates": true, "raster": false, "raster_georeferencing": false, "vector": false, "ai": false}'::jsonb, TRUE),
                ('plus', 'Plus', 100, 30, '{"coordinates": true, "raster": true, "raster_georeferencing": true, "vector": true, "ai": false}'::jsonb, TRUE),
                ('pro', 'Pro', 200, 30, '{"coordinates": true, "raster": true, "raster_georeferencing": true, "vector": true, "ai": true}'::jsonb, TRUE)
            ON CONFLICT (code) DO UPDATE
            SET name = EXCLUDED.name,
                price_tnd = EXCLUDED.price_tnd,
                duration_days = EXCLUDED.duration_days,
                modules = EXCLUDED.modules,
                active = EXCLUDED.active
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS payments (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
                plan_code TEXT NOT NULL REFERENCES plans(code),
                amount NUMERIC(10, 2) NOT NULL,
                currency TEXT NOT NULL DEFAULT 'TND',
                payment_method TEXT NOT NULL DEFAULT 'bank_transfer',
                bank_reference TEXT NOT NULL UNIQUE,
                proof_url TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                paid_at TIMESTAMPTZ,
                approved_at TIMESTAMPTZ,
                approved_by BIGINT REFERENCES app_users(id),
                notes TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS payments_user_status_idx
            ON payments (user_id, status, plan_code)
            """
        )
        ensure_integrity_constraints(conn)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subscriptions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
                plan_code TEXT NOT NULL REFERENCES plans(code),
                payment_id BIGINT REFERENCES payments(id),
                status TEXT NOT NULL DEFAULT 'active',
                current_period_start TIMESTAMPTZ NOT NULL,
                current_period_end TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subscription_logs (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                old_value JSONB,
                new_value JSONB,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.execute(
            """
            CREATE OR REPLACE FUNCTION set_payment_approval_timestamp()
            RETURNS TRIGGER AS $$
            BEGIN
                IF NEW.status = 'approved'
                   AND OLD.status IS DISTINCT FROM 'approved'
                   AND NEW.approved_at IS NULL THEN
                    NEW.approved_at := NOW();
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp
            """
        )
        conn.execute(
            """
            DROP TRIGGER IF EXISTS trg_set_payment_approval_timestamp ON payments
            """
        )
        conn.execute(
            """
            CREATE TRIGGER trg_set_payment_approval_timestamp
            BEFORE UPDATE OF status ON payments
            FOR EACH ROW
            EXECUTE FUNCTION set_payment_approval_timestamp()
            """
        )
        install_subscription_rules(conn)
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
            UPDATE app_users
            SET status = BTRIM(status),
                payment_plan = LOWER(BTRIM(payment_plan)),
                active_plan = LOWER(BTRIM(active_plan)),
                subscription_status = LOWER(BTRIM(subscription_status))
            WHERE status <> BTRIM(status)
               OR payment_plan <> LOWER(BTRIM(payment_plan))
               OR active_plan <> LOWER(BTRIM(active_plan))
               OR subscription_status <> LOWER(BTRIM(subscription_status))
            """
        )
        conn.execute(
            """
            UPDATE app_users
            SET payment_plan = CASE
                WHEN role = 'admin' THEN 'admin'
                WHEN status IN ('paid', 'approved') AND payment_plan = 'free' THEN 'plus'
                ELSE payment_plan
            END
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
                signature TEXT,
                signature_algorithm TEXT,
                release_label TEXT,
                installer_filename TEXT,
                installer_size_bytes BIGINT,
                required BOOLEAN NOT NULL DEFAULT FALSE,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_sessions (
                id TEXT PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
                device_id TEXT,
                device_name TEXT,
                client_name TEXT,
                app_version TEXT,
                client_ip TEXT,
                user_agent TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                revoked_at TIMESTAMPTZ,
                revoked_reason TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS app_sessions_user_active_idx
            ON app_sessions (user_id)
            WHERE revoked_at IS NULL
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS app_sessions_one_active_user
            ON app_sessions (user_id)
            WHERE revoked_at IS NULL
            """
        )
        conn.execute("ALTER TABLE app_releases ADD COLUMN IF NOT EXISTS installer_filename TEXT")
        conn.execute("ALTER TABLE app_releases ADD COLUMN IF NOT EXISTS installer_size_bytes BIGINT")
        conn.execute("ALTER TABLE app_releases ADD COLUMN IF NOT EXISTS signature TEXT")
        conn.execute("ALTER TABLE app_releases ADD COLUMN IF NOT EXISTS signature_algorithm TEXT")
        conn.execute("ALTER TABLE app_releases ADD COLUMN IF NOT EXISTS release_label TEXT")
        conn.execute(
            """
            UPDATE app_releases
            SET release_label = CASE
                WHEN version = '1.2.1' THEN 'GeoMapper Pro Beta v1.2.1'
                ELSE release_label
            END
            WHERE version = '1.2.1'
              AND (release_label IS NULL OR release_label = 'GeoMapper Pro v1.2.1')
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS support_messages (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                category TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analytics_events (
                id BIGSERIAL PRIMARY KEY,
                event_name TEXT NOT NULL,
                session_id TEXT,
                page TEXT,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
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
        release_version = os.getenv("APP_LATEST_VERSION", "1.0.3").strip() or "1.0.3"
        release_display_version = os.getenv(
            "APP_DISPLAY_VERSION",
            "1.0" if release_channel == "stable" else release_version,
        ).strip() or release_version
        release_min_supported = os.getenv("APP_MIN_SUPPORTED_VERSION", "1.0").strip() or "1.0"
        default_download_url = os.getenv(
            "GEOMAPPER_DOWNLOAD_URL",
            "https://github.com/MOUHANEDXIX/geomapper-pro-downloads/releases/download/v1.0.3/GeoMapperProSetup.exe",
        ).strip()
        release_download_url = os.getenv("APP_DOWNLOAD_URL", default_download_url).strip() or default_download_url
        release_notes = os.getenv(
            "APP_RELEASE_NOTES",
            "GeoMapper Pro 1.0: stable core GIS build with fixed account creation/email verification reachability, bundled GDAL/PROJ data, bundled rasterio and pyogrio compiled extensions, coordinate, raster, vector, account, and updater workflows.",
        )
        release_sha256 = (
            os.getenv("APP_RELEASE_SHA256", "F3D6452BF3FD610B9B21E994F5F3BB0E136070AC66E7697EF1BA463A4917004D").strip()
            or None
        )
        release_signature = (
            os.getenv(
                "APP_RELEASE_SIGNATURE",
                "PQ6zf/DkeYGxY3jaqFTKj1u40/xAG6GtJ5WAXQwIN8kn0OCcc6UwqDl8Gx2aChxkoIluRkCv1rtK2ZIT2hojBw==",
            ).strip()
            or None
        )
        release_signature_algorithm = (
            os.getenv("APP_RELEASE_SIGNATURE_ALGORITHM", "ed25519-sha256").strip().lower() or None
            if release_signature
            else None
        )
        release_label = os.getenv("APP_RELEASE_LABEL", f"GeoMapper Pro Stable v{release_display_version}").strip() or None
        release_installer_filename = os.getenv("APP_INSTALLER_FILENAME", "GeoMapperProSetup.exe").strip() or "GeoMapperProSetup.exe"
        installer_size_raw = os.getenv("APP_INSTALLER_SIZE_BYTES", "210600810").strip()
        release_installer_size = int(installer_size_raw) if installer_size_raw.isdigit() else None
        release_required = os.getenv("APP_UPDATE_REQUIRED", "false").strip().lower() in {"1", "true", "yes"}

        active_release = conn.execute(
            """
            SELECT id, version, min_supported_version, download_url,
                   release_notes, sha256, signature, signature_algorithm,
                   release_label, installer_filename,
                   installer_size_bytes, required
            FROM app_releases
            WHERE channel = %s
              AND is_active = TRUE
            LIMIT 1
            """,
            (release_channel,),
        ).fetchone()

        release_metadata_changed = bool(active_release) and (
            active_release.get("version") != release_version
            or active_release.get("min_supported_version") != release_min_supported
            or active_release.get("download_url") != release_download_url
            or active_release.get("release_notes") != release_notes
            or active_release.get("sha256") != release_sha256
            or active_release.get("signature") != release_signature
            or active_release.get("signature_algorithm") != release_signature_algorithm
            or active_release.get("release_label") != release_label
            or active_release.get("installer_filename") != release_installer_filename
            or active_release.get("installer_size_bytes") != release_installer_size
            or bool(active_release.get("required")) != release_required
        )
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
                    signature,
                    signature_algorithm,
                    release_label,
                    installer_filename,
                    installer_size_bytes,
                    required,
                    is_active
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
                """,
                (
                    release_channel,
                    release_version,
                    release_min_supported,
                    release_download_url,
                    release_notes,
                    release_sha256,
                    release_signature,
                    release_signature_algorithm,
                    release_label,
                    release_installer_filename,
                    release_installer_size,
                    release_required,
                ),
            )
        elif release_metadata_changed and active_release.get("version") == release_version:
            conn.execute(
                """
                UPDATE app_releases
                SET version = %s,
                    min_supported_version = %s,
                    download_url = %s,
                    release_notes = %s,
                    sha256 = %s,
                    signature = %s,
                    signature_algorithm = %s,
                    release_label = %s,
                    installer_filename = %s,
                    installer_size_bytes = %s,
                    required = %s,
                    published_at = NOW()
                WHERE id = %s
                """,
                (
                    release_version,
                    release_min_supported,
                    release_download_url,
                    release_notes,
                    release_sha256,
                    release_signature,
                    release_signature_algorithm,
                    release_label,
                    release_installer_filename,
                    release_installer_size,
                    release_required,
                    active_release["id"],
                ),
            )
        elif release_metadata_changed and _is_newer_version(active_release.get("version"), release_version):
            logger.warning(
                "Ignoring older %s release metadata from environment: active=%s configured=%s",
                release_channel,
                active_release.get("version"),
                release_version,
            )

        beta_release = {
            'channel': 'beta',
            'version': '1.3.14',
            'min_supported_version': '1.3.8',
            'download_url': 'https://github.com/MOUHANEDXIX/geomapper-pro-downloads/releases/download/v1.3.14-beta/GeoMapperProBetaSetup.exe',
            'release_notes': 'GeoMapper Pro Beta 1.3.14 includes the Stable 1.0.6 raster and session-safety improvements plus the beta AI assistant and local Ollama workflow. Ordinary input Z and the numerical model remain unchanged.',
            'sha256': 'C0D976791DC1B143C598FA085CA5D51BB3233619B01E00224F60B983D41B1E75',
            'signature': 'W7Fnu7SrLUSDjWKanWgje6s7qoE1meGpEnZpDWN1NRJatwRTuNY6oOqcQHVlPgKi++/DAsaCIBaToOARtRvpCQ==',
            'signature_algorithm': 'ed25519-sha256',
            'release_label': 'GeoMapper Pro Beta v1.3.14',
            'installer_filename': 'GeoMapperProBetaSetup.exe',
            'installer_size_bytes': 213678937,
            'required': False,
        }
        active_beta = conn.execute(
            """
            SELECT id, version, min_supported_version, download_url,
                   release_notes, sha256, signature, signature_algorithm,
                   release_label, installer_filename,
                   installer_size_bytes, required
            FROM app_releases
            WHERE channel = 'beta'
              AND is_active = TRUE
            LIMIT 1
            """
        ).fetchone()
        should_publish_beta = not active_beta or _is_newer_version(beta_release["version"], active_beta.get("version"))
        if should_publish_beta:
            if active_beta:
                conn.execute(
                    """
                    UPDATE app_releases
                    SET is_active = FALSE
                    WHERE id = %s
                    """,
                    (active_beta["id"],),
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
                    signature,
                    signature_algorithm,
                    release_label,
                    installer_filename,
                    installer_size_bytes,
                    required,
                    is_active
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
                """,
                (
                    beta_release["channel"],
                    beta_release["version"],
                    beta_release["min_supported_version"],
                    beta_release["download_url"],
                    beta_release["release_notes"],
                    beta_release["sha256"],
                    beta_release["signature"],
                    beta_release["signature_algorithm"],
                    beta_release["release_label"],
                    beta_release["installer_filename"],
                    beta_release["installer_size_bytes"],
                    beta_release["required"],
                ),
            )
        elif active_beta.get("version") == beta_release["version"]:
            beta_metadata_changed = any(
                active_beta.get(key) != beta_release[key]
                for key in (
                    "min_supported_version",
                    "download_url",
                    "release_notes",
                    "sha256",
                    "signature",
                    "signature_algorithm",
                    "release_label",
                    "installer_filename",
                    "installer_size_bytes",
                )
            ) or bool(active_beta.get("required")) != beta_release["required"]
            if beta_metadata_changed:
                conn.execute(
                    """
                    UPDATE app_releases
                    SET min_supported_version = %s,
                        download_url = %s,
                        release_notes = %s,
                        sha256 = %s,
                        signature = %s,
                        signature_algorithm = %s,
                        release_label = %s,
                        installer_filename = %s,
                        installer_size_bytes = %s,
                        required = %s,
                        published_at = NOW()
                    WHERE id = %s
                    """,
                    (
                        beta_release["min_supported_version"],
                        beta_release["download_url"],
                        beta_release["release_notes"],
                        beta_release["sha256"],
                        beta_release["signature"],
                        beta_release["signature_algorithm"],
                        beta_release["release_label"],
                        beta_release["installer_filename"],
                        beta_release["installer_size_bytes"],
                        beta_release["required"],
                        active_beta["id"],
                    ),
                )
        harden_backend_schema(conn)


def init_default_admin():
    """Create the configured administrator, refusing ordinary identity collisions."""
    from security import hash_password

    init_db()

    username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@geotun.local")
    password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")

    with get_db() as conn:
        # Multiple backend workers may bootstrap together. Serialize the
        # administrator's existence check and creation across those workers.
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended('geomapper-default-admin', 0))")
        # Never infer administrator authority from a mutable username/email.
        # An existing ordinary account is a configuration error, not an admin.
        existing = conn.execute(
            """
            SELECT id, role FROM app_users
            WHERE LOWER(username) = LOWER(%s)
               OR LOWER(email) = LOWER(%s)
            """,
            (username, email),
        ).fetchone()

        if existing:
            if existing.get("role") != "admin":
                raise RuntimeError(
                    "Configured administrator identity belongs to a non-administrator account. "
                    "Resolve the identity collision before starting the backend."
                )
            # Bootstrap is create-only: mutable usernames/email addresses must
            # never grant privileges or reactivate an existing account.
            return

        if _is_production_environment() and password == "admin123":
            logger.error("Refusing to create a production admin with the default password.")
            raise RuntimeError("DEFAULT_ADMIN_PASSWORD must be changed before creating a production admin.")

        # The configured secret is only used for first-run creation. Existing
        # administrators keep their own password, including after recovery.
        password_hash = hash_password(password)

        # First-run bootstrap: insert the default admin with full access.
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
                active_plan,
                subscription_status,
                email_verified,
                initial_email_verified
            )
            VALUES (%s, %s, %s, 'admin', 'approved', 'active', 'admin', 'admin', 'active', TRUE, TRUE)
            """,
            (username, email, password_hash),
        )


def cleanup_expired_unverified_users() -> int:
    """Delete at most 500 expired new signups without waiting on active rows."""
    with get_db() as conn:
        rows = conn.execute(
            """
            WITH expired AS (
                SELECT id FROM app_users
                WHERE role <> 'admin'
                  AND email_verified = FALSE
                  AND initial_email_verified = FALSE
                  AND email_verification_expires_at IS NOT NULL
                  AND email_verification_expires_at <= NOW()
                ORDER BY email_verification_expires_at, id
                LIMIT 500
                FOR UPDATE SKIP LOCKED
            )
            DELETE FROM app_users AS account USING expired
            WHERE account.id = expired.id
            RETURNING account.id
            """
        ).fetchall()

    return len(rows)


def expire_subscriptions() -> int:
    """Run the existing idempotent expiry function without changing its policy."""
    with get_db() as conn:
        row = conn.execute("SELECT expire_old_subscriptions() AS expired_count").fetchone()
    return int(row["expired_count"])
