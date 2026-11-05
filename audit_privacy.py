"""Explicit historical audit minimization; never called by startup or routes."""
from __future__ import annotations

SUBSCRIPTION_SNAPSHOT_KEYS = (
    "status", "payment_plan", "requested_plan", "active_plan", "subscription_status",
    "subscription_started_at", "subscription_expires_at", "last_payment_id",
)


class AuditPrivacyPreflightError(RuntimeError):
    """Stop before changing history when the reviewed scope no longer matches."""


def historical_audit_report(connection) -> dict:
    """Describe known old-value snapshots by ID without returning their contents."""
    candidates = connection.execute("""SELECT id FROM subscription_logs
        WHERE event_type='payment_approved' AND jsonb_typeof(old_value)='object'
          AND old_value - %s::text[] <> '{}'::jsonb ORDER BY id""",
        (list(SUBSCRIPTION_SNAPSHOT_KEYS),)).fetchall()
    unsupported = connection.execute("""SELECT id FROM subscription_logs
        WHERE event_type='payment_approved' AND old_value IS NOT NULL
          AND jsonb_typeof(old_value)<>'object' ORDER BY id""").fetchall()
    return {"candidate_ids": [row["id"] for row in candidates],
            "unsupported_ids": [row["id"] for row in unsupported]}


def sanitize_historical_audits(connection, *, expected_candidates: int) -> list[int]:
    """Minimize reviewed old snapshots atomically; retain every audit/payment row.

    Caller must provide a transaction and must have reviewed backup/retention.
    All event IDs/timestamps, new values and allowed subscription fields remain.
    Unknown old JSON shapes stop the operation instead of being discarded.
    """
    if expected_candidates < 0:
        raise ValueError("Expected candidate count must be nonnegative.")
    connection.execute("LOCK TABLE subscription_logs IN SHARE ROW EXCLUSIVE MODE")
    report = historical_audit_report(connection)
    if report["unsupported_ids"]:
        raise AuditPrivacyPreflightError("Unsupported historical snapshot shapes require explicit review.")
    if len(report["candidate_ids"]) != expected_candidates:
        raise AuditPrivacyPreflightError("Historical candidate count changed; rerun the read-only preflight.")
    if not report["candidate_ids"]:
        return []
    rows = connection.execute("""UPDATE subscription_logs AS log
        SET old_value=COALESCE((
            SELECT jsonb_object_agg(item.key,item.value)
            FROM jsonb_each(log.old_value) AS item(key,value)
            WHERE item.key=ANY(%s::text[])
        ), '{}'::jsonb)
        WHERE log.id=ANY(%s::bigint[]) RETURNING id""",
        (list(SUBSCRIPTION_SNAPSHOT_KEYS), report["candidate_ids"])).fetchall()
    return sorted(row["id"] for row in rows)
