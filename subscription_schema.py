"""Forward-only subscription renewal scheduling and explicit premium suspension."""
from __future__ import annotations


def install_subscription_rules(connection):
    """Install idempotent rules after the base account/payment tables exist."""
    connection.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS subscription_suspended BOOLEAN NOT NULL DEFAULT FALSE")
    connection.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS next_plan TEXT")
    connection.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS next_plan_effective_at TIMESTAMPTZ")
    connection.execute(REFRESH_USER_SQL)
    connection.execute(REFRESH_ALL_SQL)
    connection.execute(LOCK_PAYMENT_USER_SQL)
    connection.execute("DROP TRIGGER IF EXISTS trg_lock_payment_user_before_insert ON payments")
    connection.execute("""CREATE TRIGGER trg_lock_payment_user_before_insert
        BEFORE INSERT ON payments FOR EACH ROW EXECUTE FUNCTION lock_payment_user_before_insert()""")
    connection.execute(ACTIVATE_PAYMENT_SQL)
    connection.execute("DROP TRIGGER IF EXISTS trg_activate_subscription_after_payment ON payments")
    connection.execute("""CREATE TRIGGER trg_activate_subscription_after_payment
        AFTER UPDATE OF status ON payments FOR EACH ROW EXECUTE FUNCTION activate_subscription_after_payment()""")
    connection.execute("""CREATE OR REPLACE FUNCTION expire_old_subscriptions() RETURNS INTEGER
        LANGUAGE plpgsql AS $$ BEGIN RETURN refresh_subscription_states(); END; $$""")


REFRESH_USER_SQL = """
CREATE OR REPLACE FUNCTION refresh_user_subscription(p_user_id BIGINT)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
    current_user_row app_users%ROWTYPE;
    due subscriptions%ROWTYPE;
    upcoming subscriptions%ROWTYPE;
    changed BOOLEAN := FALSE;
BEGIN
    SELECT * INTO current_user_row FROM app_users WHERE id=p_user_id FOR UPDATE;
    IF NOT FOUND OR current_user_row.role='admin' THEN RETURN FALSE; END IF;

    IF current_user_row.subscription_status<>'active'
       OR current_user_row.subscription_expires_at IS NULL
       OR current_user_row.subscription_expires_at<=NOW() THEN
        SELECT * INTO due FROM subscriptions
        WHERE user_id=p_user_id AND status='scheduled'
          AND current_period_start<=NOW() AND current_period_end>NOW()
        ORDER BY current_period_start DESC,id DESC LIMIT 1 FOR UPDATE;
        IF FOUND THEN
            UPDATE subscriptions SET status='active' WHERE id=due.id;
            UPDATE app_users
            SET status='approved',payment_plan=due.plan_code,active_plan=due.plan_code,subscription_status='active',
                subscription_started_at=due.current_period_start,subscription_expires_at=due.current_period_end,
                last_payment_id=due.payment_id
            WHERE id=p_user_id;
            INSERT INTO subscription_logs(user_id,event_type,old_value,new_value)
            VALUES(p_user_id,'subscription_activated',NULL,jsonb_build_object(
                'subscription_id',due.id,'plan_code',due.plan_code,
                'current_period_start',due.current_period_start,'current_period_end',due.current_period_end));
            changed := TRUE;
        ELSIF current_user_row.subscription_status='active'
              AND current_user_row.subscription_expires_at IS NOT NULL
              AND current_user_row.subscription_expires_at<=NOW() THEN
            UPDATE app_users SET subscription_status='expired',status='awaiting_payment',active_plan='free'
            WHERE id=p_user_id;
            INSERT INTO subscription_logs(user_id,event_type,old_value,new_value)
            VALUES(p_user_id,'subscription_expired',NULL,jsonb_build_object(
                'subscription_expires_at',current_user_row.subscription_expires_at,
                'last_payment_id',current_user_row.last_payment_id));
            changed := TRUE;
        END IF;
    END IF;

    UPDATE subscriptions SET status='expired'
    WHERE user_id=p_user_id AND status IN ('active','scheduled') AND current_period_end<=NOW();

    SELECT * INTO upcoming FROM subscriptions
    WHERE user_id=p_user_id AND status='scheduled' AND current_period_end>NOW()
    ORDER BY current_period_start,id LIMIT 1;
    UPDATE app_users SET next_plan=upcoming.plan_code,next_plan_effective_at=upcoming.current_period_start
    WHERE id=p_user_id
      AND (next_plan IS DISTINCT FROM upcoming.plan_code
           OR next_plan_effective_at IS DISTINCT FROM upcoming.current_period_start);
    RETURN changed;
END;
$$
"""


REFRESH_ALL_SQL = """
CREATE OR REPLACE FUNCTION refresh_subscription_states()
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
    item RECORD;
    changed_count INTEGER := 0;
BEGIN
    FOR item IN SELECT id FROM app_users
        WHERE role<>'admin' AND (subscription_status='active' OR next_plan IS NOT NULL)
        ORDER BY id
    LOOP
        IF refresh_user_subscription(item.id) THEN changed_count := changed_count+1; END IF;
    END LOOP;
    RETURN changed_count;
END;
$$
"""


LOCK_PAYMENT_USER_SQL = """
CREATE OR REPLACE FUNCTION lock_payment_user_before_insert()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    -- Lock the account before the payment foreign key acquires its row lock.
    -- Concurrent approvals then use one consistent lock order.
    PERFORM 1 FROM app_users WHERE id=NEW.user_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Unknown payment user: %',NEW.user_id; END IF;
    RETURN NEW;
END;
$$
"""


ACTIVATE_PAYMENT_SQL = """
CREATE OR REPLACE FUNCTION activate_subscription_after_payment()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    plan_days INTEGER;
    period_start TIMESTAMPTZ;
    period_end TIMESTAMPTZ;
    current_user_row app_users%ROWTYPE;
    tail subscriptions%ROWTYPE;
    previous_user JSONB;
    schedule_future BOOLEAN := FALSE;
BEGIN
    IF NEW.status='approved' AND OLD.status IS DISTINCT FROM 'approved' THEN
        SELECT duration_days INTO plan_days FROM plans WHERE code=NEW.plan_code AND active=TRUE;
        IF plan_days IS NULL OR plan_days<=0 THEN
            RAISE EXCEPTION 'Invalid subscription plan: %',NEW.plan_code;
        END IF;

        -- All approvals, scheduled transitions and explicit suspension use the
        -- same account row lock; a retry cannot append the same payment twice.
        PERFORM refresh_user_subscription(NEW.user_id);
        SELECT * INTO current_user_row FROM app_users WHERE id=NEW.user_id FOR UPDATE;
        previous_user := jsonb_build_object(
            'status',current_user_row.status,'payment_plan',current_user_row.payment_plan,
            'requested_plan',current_user_row.requested_plan,'active_plan',current_user_row.active_plan,
            'subscription_status',current_user_row.subscription_status,
            'subscription_started_at',current_user_row.subscription_started_at,
            'subscription_expires_at',current_user_row.subscription_expires_at,
            'last_payment_id',current_user_row.last_payment_id);

        SELECT * INTO tail FROM subscriptions
        WHERE user_id=NEW.user_id AND status='scheduled' AND current_period_end>NOW()
        ORDER BY current_period_end DESC,id DESC LIMIT 1 FOR UPDATE;
        IF FOUND THEN
            period_start := GREATEST(tail.current_period_end,NOW());
            schedule_future := TRUE;
        ELSIF current_user_row.subscription_status='active'
              AND current_user_row.subscription_expires_at IS NOT NULL
              AND current_user_row.subscription_expires_at>NOW() THEN
            period_start := current_user_row.subscription_expires_at;
            schedule_future := current_user_row.active_plan IS DISTINCT FROM NEW.plan_code;
        ELSE
            period_start := NOW();
        END IF;
        period_end := period_start+make_interval(days=>plan_days);

        INSERT INTO subscriptions(user_id,plan_code,payment_id,status,current_period_start,current_period_end)
        VALUES(NEW.user_id,NEW.plan_code,NEW.id,
               CASE WHEN schedule_future THEN 'scheduled' ELSE 'active' END,period_start,period_end);
        IF NOT schedule_future THEN
            UPDATE app_users
            SET status = 'approved',payment_plan=NEW.plan_code,active_plan=NEW.plan_code,subscription_status='active',
                subscription_started_at=period_start,subscription_expires_at=period_end,last_payment_id=NEW.id
            WHERE id=NEW.user_id;
        END IF;
        -- Suspension is deliberately retained through payment and activation;
        -- paid dates continue and only the explicit Resume action lifts it.
        PERFORM refresh_user_subscription(NEW.user_id);
        INSERT INTO subscription_logs(user_id,event_type,old_value,new_value)
        VALUES(NEW.user_id,'payment_approved',previous_user,jsonb_build_object(
            'payment_id',NEW.id,'plan_code',NEW.plan_code,
            'current_period_start',period_start,'current_period_end',period_end));
    END IF;
    RETURN NEW;
END;
$$
"""
