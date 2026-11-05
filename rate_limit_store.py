"""Opt-in PostgreSQL sliding-window storage; schema installation is explicit.

Only keyed digests and timestamps reach the database. Each decision commits in
its own transaction so a subsequent failed login/payment cannot undo a budget.
"""

from __future__ import annotations

import base64
import binascii
from datetime import timedelta
import hashlib
import hmac
import json
import os
from typing import NamedTuple

import psycopg


CONNECT_TIMEOUT_SECONDS = 2
LOCK_TIMEOUT_MS = 500
STATEMENT_TIMEOUT_MS = 1000
IDLE_TRANSACTION_TIMEOUT_MS = 3000
MAX_CLEANUP_BATCH = 1000
MAX_BUDGET = 60
MAX_WINDOW_SECONDS = 900


class ConfigurationError(RuntimeError):
    """Shared limiting was selected without usable, explicit configuration."""


class StoreUnavailable(RuntimeError):
    """A shared decision could not be durably completed."""


class Configuration(NamedTuple):
    database_url: str
    key_secret: bytes


def configuration_from_environment() -> Configuration:
    """Validate configuration without connecting or revealing secret values."""
    database_url = os.getenv("RATE_LIMIT_DATABASE_URL") or os.getenv("DATABASE_URL", "")
    encoded_secret = os.getenv("RATE_LIMIT_KEY_SECRET", "")
    if not database_url.strip() or len(database_url) > 8192 or not encoded_secret or len(encoded_secret) > 172:
        raise ConfigurationError("PostgreSQL rate limiting requires a database URL and a base64 key secret.")
    try:
        # Require explicit padding and reject whitespace/non-base64 characters.
        # Both the standard and URL-safe alphabets are accepted for operators.
        secret = base64.b64decode(encoded_secret, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ConfigurationError("RATE_LIMIT_KEY_SECRET must encode 32 to 128 random bytes as base64.") from None
    if not 32 <= len(secret) <= 128:
        raise ConfigurationError("RATE_LIMIT_KEY_SECRET must encode 32 to 128 random bytes as base64.")
    return Configuration(database_url.strip(), secret)


def bucket_keys(action: str, client_ip: str, identifier: str | None, *, identifier_limited: bool) -> list[bytes]:
    """Derive private keys with the exact existing identifier normalization."""
    secret = configuration_from_environment().key_secret
    normalized = (identifier or "").strip().lower()
    scopes = [["client", action, client_ip]]
    if normalized and identifier_limited:
        scopes.append(["identifier", action, normalized])
    return [hmac.new(secret, b"geomapper-rate-limit/v1\0" + json.dumps(scope, ensure_ascii=False,
                     separators=(",", ":")).encode("utf-8"), hashlib.sha256).digest() for scope in scopes]


def _connection(configuration: Configuration):
    # The connect keyword overrides the connection string. SQL timeouts are
    # set locally after BEGIN, avoiding unsupported pooler startup parameters.
    return psycopg.connect(
        configuration.database_url,
        connect_timeout=CONNECT_TIMEOUT_SECONDS,
    )


def _configure_transaction(connection) -> None:
    # Only constants enter this statement; no caller-controlled SQL is used.
    # These bounds do not claim an absolute HTTP/network wall-clock deadline.
    connection.execute(
        f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT_MS}ms'; "
        f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT_MS}ms'; "
        f"SET LOCAL idle_in_transaction_session_timeout = '{IDLE_TRANSACTION_TIMEOUT_MS}ms'"
    )


def consume(keys: list[bytes], limit: int, window_seconds: int, *, client_limit: int | None = None) -> bool:
    """Atomically consume every applicable budget, or consume none.

    Upserts lock rows in deterministic order, including the concurrent first
    request and expired-row cleanup cases. The no-op update adds write/bloat
    overhead; a bounded, explicit cleanup operation handles expired rows.
    """
    if (not 1 <= limit <= MAX_BUDGET or not 1 <= window_seconds <= MAX_WINDOW_SECONDS
            or (client_limit is not None and not 1 <= client_limit <= MAX_BUDGET)
            or not 1 <= len(keys) <= 2 or any(not isinstance(key, bytes) or len(key) != 32 for key in keys)):
        raise StoreUnavailable("Shared rate limiting is unavailable.")
    # bucket_keys returns IP first, then optional account. Retain that policy
    # association even though SQL row locks must be acquired in sorted order.
    limits = {}
    for index, key in enumerate(keys):
        budget = client_limit if index == 0 and client_limit is not None else limit
        limits[key] = min(limits.get(key, budget), budget)
    try:
        configuration = configuration_from_environment()
        with _connection(configuration) as connection:
            _configure_transaction(connection)
            budgets = []
            for key in sorted(set(keys)):
                row = connection.execute(
                    "INSERT INTO geomapper_private.rate_limit_buckets AS bucket "
                    "(bucket_key, attempts, expires_at) VALUES (%s, '{}'::timestamptz[], clock_timestamp()) "
                    "ON CONFLICT (bucket_key) DO UPDATE SET bucket_key = EXCLUDED.bucket_key "
                    "RETURNING attempts",
                    (key,),
                ).fetchone()
                if row is None:
                    raise StoreUnavailable("Shared rate limiting is unavailable.")
                budgets.append((key, row[0]))
            # transaction_timestamp()/CURRENT_TIMESTAMP would include time
            # spent waiting for locks and could append already-old attempts.
            now = connection.execute("SELECT clock_timestamp()").fetchone()[0]
            cutoff = now - timedelta(seconds=window_seconds)
            current = [(key, [value for value in attempts if value > cutoff]) for key, attempts in budgets]
            if any(len(attempts) >= limits[key] for key, attempts in current):
                # Return normally to commit the no-op row locks. No attempts
                # or expiry values change, including the other empty budget.
                return False
            for key, attempts in current:
                retained = attempts + [now]
                connection.execute(
                    "UPDATE geomapper_private.rate_limit_buckets SET attempts = %s, expires_at = %s "
                    "WHERE bucket_key = %s",
                    # Keep future timestamps if the DB clock moved backward;
                    # cleanup must not discard their still-active allowance.
                    (retained, max(retained) + timedelta(seconds=window_seconds), key),
                )
        # Connection-context commit must succeed before an endpoint proceeds.
        return True
    except Exception:
        # Driver/configuration/SQL/commit failures must not expose connection
        # strings or silently create independent per-process allowances.
        raise StoreUnavailable("Shared rate limiting is unavailable.") from None


def cleanup_expired(limit: int = 100) -> int:
    """Delete one bounded batch without waiting on active request buckets."""
    if type(limit) is not int or not 1 <= limit <= MAX_CLEANUP_BATCH:
        raise ValueError(f"Cleanup limit must be between 1 and {MAX_CLEANUP_BATCH}.")
    try:
        with _connection(configuration_from_environment()) as connection:
            _configure_transaction(connection)
            rows = connection.execute(
                "WITH expired AS (SELECT bucket_key FROM geomapper_private.rate_limit_buckets "
                "WHERE expires_at <= statement_timestamp() ORDER BY expires_at, bucket_key "
                "LIMIT %s FOR UPDATE SKIP LOCKED) "
                "DELETE FROM geomapper_private.rate_limit_buckets AS bucket USING expired "
                "WHERE bucket.bucket_key = expired.bucket_key RETURNING bucket.bucket_key",
                (limit,),
            ).fetchall()
        return len(rows)
    except Exception:
        raise StoreUnavailable("Shared rate limiting is unavailable.") from None
