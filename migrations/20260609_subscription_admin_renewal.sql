-- Safe subscription/admin renewal support.
-- This migration is idempotent and does not delete tables or reset user data.
-- It normalizes accidental whitespace/case in account status fields so backend
-- access checks do not miss values such as 'approved '.

UPDATE public.app_users
SET status = BTRIM(status),
    payment_plan = LOWER(BTRIM(payment_plan)),
    active_plan = LOWER(BTRIM(active_plan)),
    subscription_status = LOWER(BTRIM(subscription_status))
WHERE status <> BTRIM(status)
   OR payment_plan <> LOWER(BTRIM(payment_plan))
   OR active_plan <> LOWER(BTRIM(active_plan))
   OR subscription_status <> LOWER(BTRIM(subscription_status));

-- Diagnostic query for admin/manual review:
-- users with stored paid plans but missing/inactive/expired subscription state.
SELECT id,
       status,
       payment_plan,
       active_plan,
       subscription_status,
       subscription_expires_at,
       last_payment_id
FROM public.app_users
WHERE role <> 'admin'
  AND (
    (status IN ('paid', 'approved') AND COALESCE(active_plan, 'free') IN ('free', ''))
    OR (
      COALESCE(active_plan, 'free') IN ('plus', 'pro')
      AND (
        COALESCE(subscription_status, '') <> 'active'
        OR subscription_expires_at IS NULL
        OR subscription_expires_at <= NOW()
      )
    )
  )
ORDER BY id;
