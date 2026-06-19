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
                ('free', 'Free', 0, 0, '{"coordinates": true, "raster": false, "vector": false, "ai": false}'::jsonb, TRUE),
                ('plus', 'Plus', 100, 30, '{"coordinates": true, "raster": true, "vector": false, "ai": false}'::jsonb, TRUE),
                ('pro', 'Pro', 200, 30, '{"coordinates": true, "raster": true, "vector": true, "ai": true}'::jsonb, TRUE)
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
            $$ LANGUAGE plpgsql
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
        conn.execute(
            """
            CREATE OR REPLACE FUNCTION activate_subscription_after_payment()
            RETURNS TRIGGER AS $$
            DECLARE
                plan_days INTEGER;
                period_start TIMESTAMPTZ;
                period_end TIMESTAMPTZ;
                previous_user JSONB;
            BEGIN
                IF NEW.status = 'approved'
                   AND OLD.status IS DISTINCT FROM 'approved' THEN
                    SELECT duration_days
                    INTO plan_days
                    FROM plans
                    WHERE code = NEW.plan_code
                      AND active = TRUE;

                    IF plan_days IS NULL OR plan_days <= 0 THEN
                        RAISE EXCEPTION 'Invalid subscription plan: %', NEW.plan_code;
                    END IF;

                    SELECT to_jsonb(u)
                    INTO previous_user
                    FROM app_users u
                    WHERE u.id = NEW.user_id;

                    SELECT CASE
                        WHEN subscription_status = 'active'
                             AND subscription_expires_at IS NOT NULL
                             AND subscription_expires_at > NOW()
                        THEN subscription_expires_at
                        ELSE NOW()
                    END
                    INTO period_start
                    FROM app_users
                    WHERE id = NEW.user_id
                    FOR UPDATE;

                    period_end := period_start + make_interval(days => plan_days);

                    INSERT INTO subscriptions (
                        user_id,
                        plan_code,
                        payment_id,
                        status,
                        current_period_start,
                        current_period_end
                    )
                    VALUES (
                        NEW.user_id,
                        NEW.plan_code,
                        NEW.id,
                        'active',
                        period_start,
                        period_end
                    );

                    UPDATE app_users
                    SET status = 'approved',
                        active_plan = NEW.plan_code,
                        subscription_status = 'active',
                        subscription_started_at = period_start,
                        subscription_expires_at = period_end,
                        last_payment_id = NEW.id
                    WHERE id = NEW.user_id;

                    INSERT INTO subscription_logs (user_id, event_type, old_value, new_value)
                    VALUES (
                        NEW.user_id,
                        'payment_approved',
                        previous_user,
                        jsonb_build_object(
                            'payment_id', NEW.id,
                            'plan_code', NEW.plan_code,
                            'current_period_start', period_start,
                            'current_period_end', period_end
                        )
                    );
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
        conn.execute(
            """
            DROP TRIGGER IF EXISTS trg_activate_subscription_after_payment ON payments
            """
        )
        conn.execute(
            """
            CREATE TRIGGER trg_activate_subscription_after_payment
            AFTER UPDATE OF status ON payments
            FOR EACH ROW
            EXECUTE FUNCTION activate_subscription_after_payment()
            """
        )
        conn.execute(
            """
            DROP FUNCTION IF EXISTS expire_old_subscriptions()
            """
        )
        conn.execute(
            """
            CREATE OR REPLACE FUNCTION expire_old_subscriptions()
            RETURNS INTEGER AS $$
            DECLARE
                expired_count INTEGER;
            BEGIN
                WITH expired_users AS (
                    UPDATE app_users
                    SET subscription_status = 'expired',
                        status = 'awaiting_payment',
                        active_plan = 'free'
                    WHERE role <> 'admin'
                      AND subscription_status = 'active'
                      AND subscription_expires_at IS NOT NULL
                      AND subscription_expires_at <= NOW()
                    RETURNING id, subscription_expires_at, last_payment_id
                ),
                expired_subscriptions AS (
                    UPDATE subscriptions s
                    SET status = 'expired'
                    FROM expired_users u
                    WHERE s.user_id = u.id
                      AND s.status = 'active'
                      AND s.current_period_end <= NOW()
                    RETURNING s.id
                ),
                inserted_logs AS (
                    INSERT INTO subscription_logs (user_id, event_type, old_value, new_value)
                    SELECT
                        id,
                        'subscription_expired',
                        NULL,
                        jsonb_build_object(
                            'subscription_expires_at', subscription_expires_at,
                            'last_payment_id', last_payment_id
                        )
                    FROM expired_users
                    RETURNING id
                )
                SELECT COUNT(*) INTO expired_count FROM expired_users;

                RETURN expired_count;
            END;
            $$ LANGUAGE plpgsql
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
        release_version = os.getenv("APP_LATEST_VERSION", "1.3.6").strip() or "1.3.6"
        release_min_supported = os.getenv("APP_MIN_SUPPORTED_VERSION", "1.2.5").strip() or "1.2.5"
        default_download_url = os.getenv(
            "GEOMAPPER_DOWNLOAD_URL",
            "https://github.com/MOUHANEDXIX/geomapper-pro-downloads/releases/download/v1.3.6-beta/GeoMapperProSetup.exe",
        ).strip()
        release_download_url = os.getenv("APP_DOWNLOAD_URL", default_download_url).strip() or default_download_url
        release_notes = os.getenv(
            "APP_RELEASE_NOTES",
            "GeoMapper Pro Beta 1.3.6: premium geomatics UI redesign with upgraded shell, dashboard, login, CRS/raster/vector/AI workspaces, and preserved workflow behavior.",
        )
        release_sha256 = os.getenv(
            "APP_RELEASE_SHA256",
            "5EA990F425338F92D841C8907F7A084153D2574301B7E2C573DFA12994121AF3",
        ).strip() or None
        release_signature = os.getenv(
            "APP_RELEASE_SIGNATURE",
            "DiGMBvvrDypzo8XRuaex/u9Dfi/+soNuvbbn1QKqDvOV2g1A3Oh6Qix2V45/zhmeW483COyOxEywfA0Y78CnCg==",
        ).strip() or None
        release_signature_algorithm = (
            os.getenv("APP_RELEASE_SIGNATURE_ALGORITHM", "ed25519-sha256").strip().lower() or None
            if release_signature
            else None
        )
        release_label = os.getenv("APP_RELEASE_LABEL", f"GeoMapper Pro Beta v{release_version}").strip() or None
        release_installer_filename = os.getenv("APP_INSTALLER_FILENAME", "GeoMapperProSetup.exe").strip() or "GeoMapperProSetup.exe"
        installer_size_raw = os.getenv("APP_INSTALLER_SIZE_BYTES", "204348867").strip()
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
        elif active_release.get("version") == release_version:
            metadata_changed = (
                active_release.get("min_supported_version") != release_min_supported
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
            if metadata_changed:
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
                    status = 'approved',
                    account_state = 'active',
                    payment_plan = 'admin',
                    active_plan = 'admin',
                    subscription_status = 'active',
                    email_verified = TRUE,
                    initial_email_verified = TRUE,
                    email_verification_code = NULL,
                    email_verification_expires_at = NULL
                WHERE id = %s
                """,
                (existing["id"],),
            )
            return

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
