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
    -- Worker runtime role (execution only; least privilege granted in migrations).
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nlw_worker') THEN
        CREATE ROLE nlw_worker LOGIN PASSWORD 'nlw_worker'
            NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
    -- Non-login role that owns the worker-only SECURITY DEFINER resolver.
    -- BYPASSRLS applies only inside that function; it is never a connection role.
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nlw_rls_bypass') THEN
        CREATE ROLE nlw_rls_bypass NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE nlw TO nlw_app;
GRANT USAGE ON SCHEMA public TO nlw_app;
GRANT CONNECT ON DATABASE nlw TO nlw_worker;
GRANT USAGE ON SCHEMA public TO nlw_worker;
-- Let the owner/migration role reassign the resolver's ownership to the bypass role.
GRANT nlw_rls_bypass TO nlw;
