# Backend database migrations

How schema and data changes are managed for the account backend.

## Schema

The full schema is bootstrapped and kept up to date by `init_db()` in
`backend/database.py`. Every statement there is idempotent
(`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`,
`CREATE OR REPLACE FUNCTION`), and it runs automatically on every backend
startup, so a fresh database and an existing one both converge to the same
schema without manual steps.

When you change the schema, change `init_db()` and keep the new statements
idempotent.

## This folder

`migrations/` holds **manual, one-off operational scripts** — data repairs
and diagnostics that should not run automatically on startup. They are
executed by hand (for example in the Supabase SQL editor).

Rules for new scripts:

- Name them `YYYYMMDD_short_description.sql` so they sort chronologically.
- Make them idempotent: running a script twice must be harmless.
- Never drop tables or delete verified user data.
- Start the file with a comment describing what it does and why.
