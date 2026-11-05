"""Shared transaction coordination for website and desktop payment requests."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4


def lock_payment_request(connection, user_id: int, plan_code: str) -> None:
    """Serialize a user's plan requests until their database transaction ends."""
    connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                       (f"customer-payment:{user_id}:{plan_code}",))


def new_payment_reference(plan_code: str, user_id: int, *, admin: bool = False) -> str:
    """Keep readable references unique across fast retries and parallel workers."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    prefix = "GMP-ADMIN" if admin else "GMP"
    return f"{prefix}-{plan_code.upper()}-{user_id}-{stamp}-{uuid4().hex[:12].upper()}"
