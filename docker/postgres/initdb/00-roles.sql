-- Role provisioning (bootstrap, NOT an Alembic concern).
--
-- Runs once on fresh Postgres volume init (docker-entrypoint-initdb.d), as the
-- POSTGRES_USER (nlw, the owner/migration role) in the POSTGRES_DB (nlw).
--
-- Creates the restricted application runtime role. It must never be a superuser
-- and must never have BYPASSRLS. Table privileges and RLS policies are applied
-- by Alembic migration 0003, not here.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nlw_app') THEN
        CREATE ROLE nlw_app LOGIN PASSWORD 'nlw_app'
            NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE nlw TO nlw_app;
GRANT USAGE ON SCHEMA public TO nlw_app;
