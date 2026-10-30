-- Additive integrity migration. No account/payment rows are changed or removed.
-- Run scripts/check_backend_integrity.py first. Resolve reported ID groups
-- explicitly before applying this migration; back up the database beforehand.
-- Customer bank-transfer requests are unique while pending. Administrator
-- manual renewals remain separate and are approved within their transaction.
BEGIN;
LOCK TABLE public.app_users, public.payments IN SHARE ROW EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.app_users GROUP BY LOWER(username) HAVING COUNT(*) > 1)
       OR EXISTS (SELECT 1 FROM public.app_users GROUP BY LOWER(email) HAVING COUNT(*) > 1)
       OR EXISTS (
           SELECT 1 FROM public.payments
           WHERE status = 'pending' AND payment_method = 'bank_transfer'
           GROUP BY user_id, plan_code HAVING COUNT(*) > 1
       ) THEN
        RAISE EXCEPTION 'Uniqueness migration blocked by existing conflicts'
            USING HINT = 'Run the read-only integrity preflight and resolve records explicitly. No automatic merge/deletion is performed.';
    END IF;
END;
$$;
CREATE UNIQUE INDEX IF NOT EXISTS app_users_username_ci_uq ON public.app_users (LOWER(username));
CREATE UNIQUE INDEX IF NOT EXISTS app_users_email_ci_uq ON public.app_users (LOWER(email));
CREATE UNIQUE INDEX IF NOT EXISTS payments_one_pending_customer_plan_uq
    ON public.payments (user_id, plan_code)
    WHERE status = 'pending' AND payment_method = 'bank_transfer';
COMMIT;
