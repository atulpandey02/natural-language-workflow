"""Idempotent role provisioning on a REAL PostgreSQL (M12A-Prep §D, O.12).

Two cluster shapes:
  * FRESH — the initdb script already created all seven roles (pg_stack);
  * EXISTING (M11) — only the five pre-P3A roles exist, exactly like the staging
    host; ``ensure`` must create the two missing NOLOGIN owners and nothing else.
Incompatible attributes on an existing role are an error, never altered.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace

import psycopg
import pytest
from testcontainers.postgres import PostgresContainer

from nlw.ops import roles

pytestmark = pytest.mark.integration

M11_ROLES_SQL = """
CREATE ROLE nlw_app LOGIN PASSWORD 'x' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE nlw_worker LOGIN PASSWORD 'x' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE nlw_scheduler LOGIN PASSWORD 'x'
    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE nlw_rls_bypass NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE nlw_workspace_bootstrap NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT nlw_rls_bypass TO nlw;
GRANT nlw_workspace_bootstrap TO nlw;
"""


@pytest.fixture
def m11_cluster() -> Iterator[str]:
    """A throwaway Postgres whose owner is `nlw` and which has ONLY the M11 roles."""
    with PostgresContainer("postgres:16", username="nlw", password="nlw", dbname="nlw") as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute(M11_ROLES_SQL)
        yield url


def _attrs(url: str) -> dict[str, roles.RoleModel]:
    with psycopg.connect(url) as c:
        return roles.read_roles(c)


def test_existing_m11_cluster_gets_exactly_the_missing_roles(m11_cluster: str) -> None:
    with psycopg.connect(m11_cluster, autocommit=True) as c:
        assert roles.verify_roles(c, require_all=False) == []
        assert any("missing" in p for p in roles.verify_roles(c, require_all=True))
        created = roles.ensure_roles(c)
        # The two P3A/P3B owners and the DORMANT ingest runtime and dispatcher
        # roles (ADR-031/032).
        assert created == [
            "nlw_membership_admin", "nlw_ctx_verifier", "nlw_ingest", "nlw_ingest_dispatch",
        ]  # fmt: skip
        assert roles.verify_roles(c, require_all=True) == []
        # Idempotent: a second run creates nothing and still verifies.
        assert roles.ensure_roles(c) == []
    attrs = _attrs(m11_cluster)
    assert attrs["nlw_membership_admin"] == roles.RoleModel(False, False, True)
    assert attrs["nlw_ctx_verifier"] == roles.RoleModel(False, False, False)
    assert attrs["nlw_ingest"] == roles.RoleModel(False, False, False)  # NOLOGIN: dormant
    assert attrs["nlw_ingest_dispatch"] == roles.RoleModel(False, False, False)
    with psycopg.connect(m11_cluster) as c:
        # A runtime role: never granted to the owner (unlike the owner roles),
        # NOINHERIT, member of nothing.
        assert c.execute(
            "SELECT rolinherit FROM pg_roles WHERE rolname = 'nlw_ingest'"
        ).fetchone() == (False,)
        assert c.execute(
            "SELECT count(*) FROM pg_auth_members am JOIN pg_roles r ON r.oid IN "
            "(am.roleid, am.member) WHERE r.rolname = 'nlw_ingest'"
        ).fetchone() == (0,)
    # No table privileges were granted here (that belongs to migrations).
    with psycopg.connect(m11_cluster) as c:
        n = c.execute(
            "SELECT count(*) FROM information_schema.role_table_grants "
            "WHERE grantee IN ('nlw_membership_admin','nlw_ctx_verifier','nlw_ingest',"
            "'nlw_ingest_dispatch')"
        ).fetchone()
        assert n is not None and n[0] == 0


def test_incompatible_existing_role_is_an_error_not_widened(m11_cluster: str) -> None:
    with psycopg.connect(m11_cluster, autocommit=True) as c:
        c.execute("CREATE ROLE nlw_ctx_verifier NOLOGIN NOSUPERUSER BYPASSRLS")  # wrong: BYPASSRLS
        with pytest.raises(roles.RoleProvisioningError, match="nlw_ctx_verifier"):
            roles.ensure_roles(c)
        # Nothing was created or altered.
        assert "nlw_membership_admin" not in _attrs(m11_cluster)
        assert _attrs(m11_cluster)["nlw_ctx_verifier"].bypassrls is True
        c.execute("DROP ROLE nlw_ctx_verifier")
        c.execute("ALTER ROLE nlw_worker BYPASSRLS")  # a widened runtime role
        with pytest.raises(roles.RoleProvisioningError, match="nlw_worker"):
            roles.ensure_roles(c)


def test_unexpected_membership_is_reported(m11_cluster: str) -> None:
    with psycopg.connect(m11_cluster, autocommit=True) as c:
        roles.ensure_roles(c)
        c.execute("GRANT nlw_ctx_verifier TO nlw_app")  # a runtime login could assume the verifier
        problems = roles.verify_roles(c, require_all=True)
        assert any("nlw_ctx_verifier: unexpected members ['nlw_app']" in p for p in problems)


def test_fresh_cluster_from_initdb_verifies_clean(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        assert roles.verify_roles(c, require_all=True) == []
        assert roles.ensure_roles(c) == []


def test_a_widened_ingest_role_is_an_error_and_its_login_variant_is_the_only_other(
    m11_cluster: str,
) -> None:
    """ADR-031: nlw_ingest is NOLOGIN (dormant) or, where enabled, LOGIN; never
    superuser, BYPASSRLS, CREATEDB or CREATEROLE, and never anyone's member."""
    with psycopg.connect(m11_cluster, autocommit=True) as c:
        for attrs in ("NOLOGIN BYPASSRLS", "LOGIN CREATEROLE"):
            c.execute(f"CREATE ROLE nlw_ingest {attrs}")
            with pytest.raises(roles.RoleProvisioningError, match="nlw_ingest"):
                roles.ensure_roles(c)
            c.execute("DROP ROLE nlw_ingest")
        c.execute("CREATE ROLE nlw_ingest LOGIN NOINHERIT")  # an enabled ingest runtime
        assert roles.ensure_roles(c) == [
            "nlw_membership_admin", "nlw_ctx_verifier", "nlw_ingest_dispatch",
        ]  # fmt: skip
        assert roles.verify_roles(c, require_all=True) == []
        c.execute("GRANT nlw_ingest TO nlw_app")  # the API assuming the ingest role
        problems = roles.verify_roles(c, require_all=True)
        assert any("nlw_ingest: unexpected members ['nlw_app']" in p for p in problems)


def test_a_widened_dispatch_role_is_an_error_and_its_login_variant_is_the_only_other(
    m11_cluster: str,
) -> None:
    """ADR-032: nlw_ingest_dispatch is NOLOGIN (dormant) or, where enabled,
    LOGIN; never superuser, BYPASSRLS, CREATEDB or CREATEROLE, never a member."""
    with psycopg.connect(m11_cluster, autocommit=True) as c:
        for attrs in ("NOLOGIN BYPASSRLS", "LOGIN CREATEDB", "LOGIN SUPERUSER"):
            c.execute(f"CREATE ROLE nlw_ingest_dispatch {attrs}")
            with pytest.raises(roles.RoleProvisioningError, match="nlw_ingest_dispatch"):
                roles.ensure_roles(c)
            c.execute("DROP ROLE nlw_ingest_dispatch")
        c.execute("CREATE ROLE nlw_ingest_dispatch LOGIN NOINHERIT")  # an enabled dispatcher
        assert "nlw_ingest_dispatch" not in roles.ensure_roles(c)
        assert roles.verify_roles(c, require_all=True) == []
        c.execute("GRANT nlw_rls_bypass TO nlw_ingest_dispatch")  # assuming the definer owner
        problems = roles.verify_roles(c, require_all=True)
        assert any("nlw_rls_bypass: unexpected members" in p for p in problems)
