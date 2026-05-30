"""Small process-local rate limiter for sensitive public endpoints."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import defaultdict, deque

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

_attempts: dict[str, deque[float]] = defaultdict(deque)
_lock = threading.Lock()


def _enabled() -> bool:
    return os.getenv("RATE_LIMIT_ENABLED", "true").strip().lower() not in {"0", "false", "no"}


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _identifier_digest(identifier: str | None) -> str:
    normalized = (identifier or "").strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:20] if normalized else "-"


def enforce_rate_limit(request: Request, action: str, identifier: str | None = None) -> None:
    """Raise a clean 429 response when an action exceeds its configured budget."""
    if not _enabled():
        return

    limit, window_seconds = RATE_LIMITS[action]
    key = f"{action}:{_client_ip(request)}:{_identifier_digest(identifier)}"
    cutoff = time.monotonic() - window_seconds

    with _lock:
        attempts = _attempts[key]
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        if len(attempts) >= limit:
            raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
        attempts.append(time.monotonic())
