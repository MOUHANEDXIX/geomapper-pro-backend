"""Additive account/customer-request constraints with non-destructive preflight."""
from __future__ import annotations


INDEX_STATEMENTS = (
    "CREATE UNIQUE INDEX IF NOT EXISTS app_users_username_ci_uq ON app_users (LOWER(username))",
    "CREATE UNIQUE INDEX IF NOT EXISTS app_users_email_ci_uq ON app_users (LOWER(email))",
    """CREATE UNIQUE INDEX IF NOT EXISTS payments_one_pending_customer_plan_uq
       ON payments (user_id, plan_code)
       WHERE status = 'pending' AND payment_method = 'bank_transfer'""",
)


class IntegrityPreflightError(RuntimeError):
    """Existing conflicts must be reviewed explicitly; no records are removed."""

    def __init__(self, report):
        self.report = report
        counts = ", ".join(f"{key}={len(groups)}" for key, groups in report.items())
        super().__init__("Backend uniqueness migration blocked by existing conflicts: " + counts
                         + ". Run the read-only integrity preflight and resolve records explicitly.")


def integrity_conflicts(connection) -> dict[str, list[list[int]]]:
    """Return conflicting record-ID groups without copying account/profile data."""
    queries = {
        "username_case_duplicates": """SELECT ARRAY_AGG(id ORDER BY id) AS record_ids
            FROM app_users GROUP BY LOWER(username) HAVING COUNT(*) > 1 ORDER BY MIN(id)""",
        "email_case_duplicates": """SELECT ARRAY_AGG(id ORDER BY id) AS record_ids
            FROM app_users GROUP BY LOWER(email) HAVING COUNT(*) > 1 ORDER BY MIN(id)""",
        "pending_customer_payment_duplicates": """SELECT ARRAY_AGG(id ORDER BY id) AS record_ids
            FROM payments WHERE status = 'pending' AND payment_method = 'bank_transfer'
            GROUP BY user_id, plan_code HAVING COUNT(*) > 1 ORDER BY MIN(id)""",
    }
    return {key: [list(row["record_ids"]) for row in connection.execute(query).fetchall()]
            for key, query in queries.items()}


def ensure_integrity_constraints(connection) -> None:
    """Install constraints atomically after locking out concurrent writes.

    Caller must use a transaction (as database.get_db does). The pending index
    concerns customer bank-transfer requests; an administrator's transient
    manual-renewal payment remains compatible with an existing customer request.
    """
    connection.execute("LOCK TABLE app_users, payments IN SHARE ROW EXCLUSIVE MODE")
    report = integrity_conflicts(connection)
    if any(report.values()):
        raise IntegrityPreflightError(report)
    for statement in INDEX_STATEMENTS:
        connection.execute(statement)
