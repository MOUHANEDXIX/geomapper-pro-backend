"""Sensitive-endpoint limits with local storage or explicit shared PostgreSQL."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import threading
import time
from collections import defaultdict, deque
from functools import lru_cache

from fastapi import HTTPException, Request


RATE_LIMITS = {
    "login": (8, 300),
    "signup": (5, 600),
    "verify_email": (10, 600),
    "resend_code": (4, 600),
    "forgot_password": (4, 900),
    "reset_password": (8, 900),
    "change_password": (6, 900),
    "support": (4, 900),
    "analytics": (60, 60),
    "plan_request": (8, 600),
    "deactivate": (4, 900),
}

# These identifiers name accounts, recipients or authenticated users. Their
# budget must survive a client changing networks or caller-supplied headers.
IDENTIFIER_LIMITED_ACTIONS = frozenset(RATE_LIMITS) - {"analytics"}

_attempts: dict[str, deque[float]] = defaultdict(deque)
_lock = threading.Lock()


def _enabled() -> bool:
    return os.getenv("RATE_LIMIT_ENABLED", "true").strip().lower() not in {"0", "false", "no"}


def validate_rate_limit_configuration() -> str | None:
    """Reject invalid opt-in settings before startup writes; never install DDL.

    Return the selected shared database URL so staging can validate its
    destination using the same existing production-isolation guard.
    """
    if not _enabled():
        return None
    backend = os.getenv("RATE_LIMIT_BACKEND", "memory").strip().lower()
    if backend == "memory":
        return None
    if backend != "postgres":
        raise RuntimeError("RATE_LIMIT_BACKEND must be memory or postgres.")
    from rate_limit_store import configuration_from_environment
    return configuration_from_environment().database_url


def cleanup_expired_rate_limits() -> int:
    """Housekeep one shared batch; the default local store never connects."""
    if not _enabled():
        return 0
    backend = os.getenv("RATE_LIMIT_BACKEND", "memory").strip().lower()
    if backend == "memory":
        return 0
    try:
        if backend != "postgres":
            raise RuntimeError("Invalid rate-limit backend.")
        from rate_limit_store import cleanup_expired
        return cleanup_expired(1000)
    except Exception:
        # Housekeeping logs its exceptions. Suppress driver/config details and
        # their chain so connection strings never become application logs.
        raise RuntimeError("Shared rate-limit cleanup is unavailable.") from None


@lru_cache(maxsize=8)
def _proxy_networks(configuration: str) -> tuple:
    """Invalid or universal allowlists grant no forwarding-header trust."""
    if not configuration.strip():
        return ()
    try:
        networks = tuple(ipaddress.ip_network(item.strip(), strict=False)
                         for item in configuration.split(","))
    except ValueError:
        return ()
    return () if any(network.prefixlen == 0 for network in networks) else networks


def _address(value: str):
    if "%" in value:  # Scope identifiers are not valid forwarded client hosts.
        raise ValueError("Scoped forwarding address")
    return ipaddress.ip_address(value)


def _client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    try:
        address = _address(peer)
    except ValueError:
        return peer
    peer = str(address)
    networks = _proxy_networks(os.getenv("RATE_LIMIT_TRUSTED_PROXIES", ""))

    def trusted(hop):
        return any(hop in network for network in networks)

    if not trusted(address):
        return peer
    # The ASGI server must preserve the transport peer when the application
    # parses forwarding headers (Uvicorn --no-proxy-headers). Alternatively,
    # leave this allowlist empty and configure trust at the ASGI server only.
    forwarded = ",".join(request.headers.getlist("x-forwarded-for"))
    parts = forwarded.split(",")
    if not forwarded or len(forwarded) > 8192 or len(parts) > 64:
        return peer
    try:
        hops = [_address(part.strip()) for part in parts]
    except ValueError:
        return peer
    for hop in reversed(hops):
        address = hop
        if not trusted(hop):
            break
    return str(address)


def _identifier_digest(identifier: str | None) -> str:
    normalized = (identifier or "").strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:20] if normalized else "-"


def enforce_rate_limit(request: Request, action: str, identifier: str | None = None) -> None:
    """Raise a clean 429 response when an action exceeds its configured budget."""
    if not _enabled():
        return

    limit, window_seconds = RATE_LIMITS[action]
    backend = os.getenv("RATE_LIMIT_BACKEND", "memory").strip().lower()
    if backend != "memory":
        try:
            if backend != "postgres":
                raise RuntimeError("Invalid rate-limit backend.")
            from rate_limit_store import bucket_keys, consume
            keys = bucket_keys(action, _client_ip(request), identifier,
                               identifier_limited=action in IDENTIFIER_LIMITED_ACTIONS)
            allowed = consume(keys, limit, window_seconds)
        except Exception:
            raise HTTPException(status_code=503, detail="Request protection is temporarily unavailable. Please try again later.") from None
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
        return
    digest = _identifier_digest(identifier)
    keys = [f"{action}:client:{_client_ip(request)}:{digest}"]
    if digest != "-" and action in IDENTIFIER_LIMITED_ACTIONS:
        keys.append(f"{action}:identifier:{digest}")
    now = time.monotonic()
    cutoff = now - window_seconds

    with _lock:
        budgets = [_attempts[key] for key in keys]
        for attempts in budgets:
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
        if any(len(attempts) >= limit for attempts in budgets):
            raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
        # Check every applicable budget before consuming any of them.
        for attempts in budgets:
            attempts.append(now)
