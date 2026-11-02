-- Optional shared rate limiting. Apply explicitly before opting in; startup
-- does not execute this file. No account, subscription or release data changes.
BEGIN;

CREATE SCHEMA IF NOT EXISTS geomapper_private;
REVOKE ALL ON SCHEMA geomapper_private FROM PUBLIC;

CREATE TABLE IF NOT EXISTS geomapper_private.rate_limit_buckets (
    bucket_key BYTEA PRIMARY KEY CHECK (octet_length(bucket_key) = 32),
    attempts TIMESTAMPTZ[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(attempts) <= 60 AND array_position(attempts, NULL) IS NULL),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_limit_buckets_expiry_idx
    ON geomapper_private.rate_limit_buckets (expires_at);

REVOKE ALL ON TABLE geomapper_private.rate_limit_buckets FROM PUBLIC;
ALTER TABLE geomapper_private.rate_limit_buckets ENABLE ROW LEVEL SECURITY;

-- Supabase roles may not exist in plain PostgreSQL test/development clusters.
-- Explicitly remove API access even if a project's default grants differ.
DO $roles$
DECLARE api_role TEXT;
BEGIN
    FOREACH api_role IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = api_role) THEN
            EXECUTE format('REVOKE ALL ON SCHEMA geomapper_private FROM %I', api_role);
            EXECUTE format('REVOKE ALL ON TABLE geomapper_private.rate_limit_buckets FROM %I', api_role);
        END IF;
    END LOOP;
END
$roles$;

COMMENT ON TABLE geomapper_private.rate_limit_buckets IS
    'Private short-lived HMAC-keyed rate limits; never expose through the Data API.';
COMMIT;
