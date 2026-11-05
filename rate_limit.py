"""Sensitive-endpoint limits with local storage or explicit shared PostgreSQL."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import threading
import time
from collections import OrderedDict, defaultdict, deque
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

# A shared office/network needs more aggregate room than one account. These
# IP-wide budgets still stop identifier rotation, while RATE_LIMITS retains
# the tighter account/recipient protection across changing networks.
IP_RATE_LIMITS = {
    "login": (40, 300),
    "signup": (20, 600),
    "verify_email": (40, 600),
    "resend_code": (20, 600),
    "forgot_password": (20, 900),
    "reset_password": (40, 900),
    "change_password": (30, 900),
    "support": (20, 900),
    "analytics": (60, 60),
    "plan_request": (40, 600),
    "deactivate": (20, 900),
}

# These identifiers name accounts, recipients or authenticated users. Their
# budget must survive a client changing networks or caller-supplied headers.
IDENTIFIER_LIMITED_ACTIONS = frozenset(RATE_LIMITS) - {"analytics"}

_attempts: dict[str, deque[float]] = defaultdict(deque)
# Use one common retention period so expiry order follows accepted requests.
# Active budgets are never evicted to make room: that would reset protection.
MAX_MEMORY_BUCKETS = 20_000
MEMORY_RETENTION_SECONDS = max(window for _, window in RATE_LIMITS.values())
_memory_expiries: OrderedDict[str, float] = OrderedDict()
_lock = threading.Lock()


def _prune_memory(now: float) -> int:
    """Remove expired keys in expiry order; callers hold the state lock."""
    removed = 0
    while _memory_expiries:
        key, expiry = next(iter(_memory_expiries.items()))
        if expiry > now:
            break
        _memory_expiries.popitem(last=False)
        if _attempts.pop(key, None) is not None:
            removed += 1
    return removed


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
        with _lock:
            return _prune_memory(time.monotonic())
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
    client_limit, _ = IP_RATE_LIMITS[action]
    backend = os.getenv("RATE_LIMIT_BACKEND", "memory").strip().lower()
    if backend != "memory":
        try:
            if backend != "postgres":
                raise RuntimeError("Invalid rate-limit backend.")
            from rate_limit_store import bucket_keys, consume
            keys = bucket_keys(action, _client_ip(request), identifier,
                               identifier_limited=action in IDENTIFIER_LIMITED_ACTIONS)
            allowed = consume(keys, limit, window_seconds, client_limit=client_limit)
        except Exception:
            raise HTTPException(status_code=503, detail="Request protection is temporarily unavailable. Please try again later.") from None
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
        return
    digest = _identifier_digest(identifier)
    # The client budget is independent of the caller-supplied account/session.
    keys = [f"{action}:client:{_client_ip(request)}"]
    if digest != "-" and action in IDENTIFIER_LIMITED_ACTIONS:
        keys.append(f"{action}:identifier:{digest}")
    now = time.monotonic()
    cutoff = now - window_seconds

    with _lock:
        _prune_memory(now)
        budgets = [_attempts.get(key, deque()) for key in keys]
        for attempts in budgets:
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
        limits = [client_limit] + [limit] * (len(keys) - 1)
        if any(len(attempts) >= budget_limit for attempts, budget_limit in zip(budgets, limits)):
            raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
        if len(_attempts) + sum(key not in _attempts for key in keys) > MAX_MEMORY_BUCKETS:
            raise HTTPException(status_code=503, detail="Request protection is temporarily unavailable. Please try again later.")
        # Check every applicable budget before consuming any of them.
        for key, attempts in zip(keys, budgets):
            attempts.append(now)
            _attempts[key] = attempts
            _memory_expiries[key] = now + MEMORY_RETENTION_SECONDS
            _memory_expiries.move_to_end(key)
