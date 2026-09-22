#!/usr/bin/env bash
# Runtime role provisioning (bootstrap, NOT an Alembic concern).
#
# Runs ONCE on a fresh Postgres volume (docker-entrypoint-initdb.d), as the
# POSTGRES_USER (nlw, the owner/migration role) in the POSTGRES_DB (nlw).
#
# The three restricted LOGIN roles get STRONG passwords supplied by the
# environment — never hardcoded, never placed on argv, never echoed. The
# passwords are imported directly into psql with \getenv (no shell-string
# interpolation) and bound as quoted literals with :'var'. psql runs without
# -a/-e and this script never enables `set -x`, so no password is logged.
#
# FRESH-VOLUME SEMANTICS: this runs only at initial volume init, so the roles
# never pre-exist and a plain CREATE ROLE is correct. Changing the *_DB_PASSWORD
# environment variables LATER does NOT rotate an existing role's password — that
# is an explicit `ALTER ROLE ... PASSWORD` operation performed against the live
# database (see docs/runbooks/rotate-db-role-password.md).
#
# Table privileges and RLS policies are applied by Alembic migration 0003, not
# here. The roles must never be superusers and must never have BYPASSRLS.
set -euo pipefail

: "${NLW_APP_DB_PASSWORD:?NLW_APP_DB_PASSWORD is required}"
: "${NLW_WORKER_DB_PASSWORD:?NLW_WORKER_DB_PASSWORD is required}"
: "${NLW_SCHEDULER_DB_PASSWORD:?NLW_SCHEDULER_DB_PASSWORD is required}"

# Heredoc is flush-left and single-quoted: psql receives it verbatim, the
# passwords enter via \getenv (never the shell command line), and :'var' binds
# each as a properly quoted SQL literal.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_pw NLW_APP_DB_PASSWORD
\getenv worker_pw NLW_WORKER_DB_PASSWORD
\getenv scheduler_pw NLW_SCHEDULER_DB_PASSWORD

-- Restricted application runtime role: RLS + SET LOCAL app.* GUCs enforce tenant
-- isolation. Never superuser, never BYPASSRLS.
CREATE ROLE nlw_app LOGIN PASSWORD :'app_pw'
    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
-- Worker runtime role (execution only; least privilege granted in migrations).
CREATE ROLE nlw_worker LOGIN PASSWORD :'worker_pw'
    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
-- Scheduler runtime role (M8): finds due schedules, creates + enqueues runs,
-- reconciles stuck runs. Cross-tenant via role-specific RLS policies granted in
-- migrations. NEVER superuser, NEVER BYPASSRLS; no connector/secret access.
CREATE ROLE nlw_scheduler LOGIN PASSWORD :'scheduler_pw'
    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;

-- Non-login role owning the read-only SECURITY DEFINER authorization/routing
-- helpers. BYPASSRLS applies only inside those functions; never a connection
-- role. No password (NOLOGIN).
CREATE ROLE nlw_rls_bypass NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
-- Non-login role owning the workspace bootstrap write function only.
CREATE ROLE nlw_workspace_bootstrap NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
-- Non-login role owning ONLY the manage_membership function (P3A). Narrowly
-- granted (memberships DML + authz audit INSERT); never a connection role. Kept
-- separate from nlw_workspace_bootstrap so the identity-bootstrap owner does not
-- also become a general membership administrator. BYPASSRLS is required because
-- memberships/authz_audit_events are FORCE RLS and the function does its own
-- authorization; its blast radius is bounded by the migration grants + tests.
CREATE ROLE nlw_membership_admin NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;

GRANT CONNECT ON DATABASE nlw TO nlw_app;
GRANT USAGE ON SCHEMA public TO nlw_app;
GRANT CONNECT ON DATABASE nlw TO nlw_worker;
GRANT USAGE ON SCHEMA public TO nlw_worker;
GRANT CONNECT ON DATABASE nlw TO nlw_scheduler;
GRANT USAGE ON SCHEMA public TO nlw_scheduler;
-- Let the owner/migration role reassign the helper functions' ownership.
GRANT nlw_rls_bypass TO nlw;
GRANT nlw_workspace_bootstrap TO nlw;
GRANT nlw_membership_admin TO nlw;
SQL
