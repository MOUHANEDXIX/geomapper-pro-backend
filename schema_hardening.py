"""Keep backend-only tables and routines outside the public Data API surface.

The application connects as the schema owner. Browser/desktop users authenticate
through FastAPI, never by acquiring a PostgreSQL role or an RLS policy here.
"""
from __future__ import annotations


BACKEND_TABLES = (
    "app_users", "app_sessions", "payments", "plans", "subscriptions",
    "subscription_logs", "app_releases", "support_messages", "analytics_events",
)
BACKEND_FUNCTIONS = (
    "public.refresh_user_subscription(bigint)",
    "public.refresh_subscription_states()",
    "public.expire_old_subscriptions()",
    "public.lock_payment_user_before_insert()",
    "public.activate_subscription_after_payment()",
    "public.set_payment_approval_timestamp()",
)
FOREIGN_KEY_INDEXES = (
    "CREATE INDEX IF NOT EXISTS payments_approved_by_idx ON public.payments (approved_by)",
    "CREATE INDEX IF NOT EXISTS subscription_logs_user_idx ON public.subscription_logs (user_id)",
    "CREATE INDEX IF NOT EXISTS subscriptions_payment_idx ON public.subscriptions (payment_id)",
    "CREATE INDEX IF NOT EXISTS subscriptions_plan_idx ON public.subscriptions (plan_code)",
    "CREATE INDEX IF NOT EXISTS subscriptions_user_state_period_idx ON public.subscriptions "
    "(user_id, status, current_period_start, current_period_end)",
)


def harden_backend_schema(connection) -> None:
    """Apply idempotent, data-preserving privileges after schema bootstrap.

    Identifiers below are fixed application constants. Only the nine owned tables
    and six owned routines are changed; other applications and Supabase's managed
    event triggers retain their own configuration.
    """
    for table in BACKEND_TABLES:
        connection.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        connection.execute(f"REVOKE ALL ON TABLE public.{table} FROM PUBLIC")
    for signature in BACKEND_FUNCTIONS:
        connection.execute(f"ALTER FUNCTION {signature} SET search_path TO pg_catalog, public, pg_temp")
        connection.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
    for statement in FOREIGN_KEY_INDEXES:
        connection.execute(statement)
    # Plain PostgreSQL development/test clusters do not have Supabase API roles.
    # Existing project-level grants to these roles must be removed explicitly;
    # revoking from PUBLIC alone does not remove such grants.
    tables = ", ".join(f"public.{name}" for name in BACKEND_TABLES)
    functions = ", ".join(BACKEND_FUNCTIONS)
    connection.execute(f"""
        DO $backend_api_privileges$
        DECLARE api_role name;
        BEGIN
            FOR api_role IN SELECT rolname FROM pg_roles WHERE rolname IN ('anon', 'authenticated')
            LOOP
                EXECUTE format('REVOKE ALL ON TABLE {tables} FROM %I', api_role);
                EXECUTE format('REVOKE ALL ON FUNCTION {functions} FROM %I', api_role);
            END LOOP;
        END
        $backend_api_privileges$;
    """)
    # Retire only the two known legacy expression indexes when a valid unique
    # replacement has the exact same keys, expressions, predicate and access
    # method. Never remove a constraint's backing index or unrelated indexes.
    connection.execute("""
        DO $duplicate_account_indexes$
        DECLARE old_name text; replacement_name text; duplicate_name text;
        BEGIN
            FOR old_name, replacement_name IN VALUES
                ('idx_app_users_email_lower', 'app_users_email_ci_uq'),
                ('idx_app_users_username_lower', 'app_users_username_ci_uq')
            LOOP
                SELECT old_class.relname INTO duplicate_name
                FROM pg_index AS old_index
                JOIN pg_class AS old_class ON old_class.oid=old_index.indexrelid
                JOIN pg_namespace AS old_schema ON old_schema.oid=old_class.relnamespace
                JOIN pg_index AS replacement ON replacement.indrelid=old_index.indrelid
                JOIN pg_class AS replacement_class ON replacement_class.oid=replacement.indexrelid
                JOIN pg_namespace AS replacement_schema ON replacement_schema.oid=replacement_class.relnamespace
                WHERE old_schema.nspname='public' AND replacement_schema.nspname='public'
                  AND old_class.relname=old_name AND replacement_class.relname=replacement_name
                  AND replacement.indisunique AND replacement.indisvalid
                  AND old_index.indkey=replacement.indkey
                  AND old_index.indclass=replacement.indclass
                  AND old_index.indcollation=replacement.indcollation
                  AND old_index.indoption=replacement.indoption
                  -- pg_node_tree text can retain parser locations (notably
                  -- PostgreSQL 16). Compare the reconstructed expressions so
                  -- equivalent definitions do not depend on source offsets.
                  AND pg_get_expr(old_index.indexprs, old_index.indrelid)
                      IS NOT DISTINCT FROM pg_get_expr(replacement.indexprs, replacement.indrelid)
                  AND pg_get_expr(old_index.indpred, old_index.indrelid)
                      IS NOT DISTINCT FROM pg_get_expr(replacement.indpred, replacement.indrelid)
                  AND old_class.relam=replacement_class.relam
                  AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conindid=old_index.indexrelid);
                IF duplicate_name IS NOT NULL THEN
                    EXECUTE format('DROP INDEX public.%I', duplicate_name);
                END IF;
            END LOOP;
        END
        $duplicate_account_indexes$;
    """)
