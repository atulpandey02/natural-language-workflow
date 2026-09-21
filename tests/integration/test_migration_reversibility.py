"""Migration reversibility for the P1A migration (and the full chain).

Exercises the required matrix against a real Postgres with the runtime roles
bootstrapped: head -> previous -> head -> base -> head. Proves the P1A migration
(and every migration below it) downgrades and re-upgrades cleanly, and that the
prior ``users``/``connectors`` grants+policies are restored on downgrade.
"""

from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.config import Config

pytestmark = pytest.mark.integration

_HEAD = "0011_identity_connector_authz"
_PREV = "0010_readiness_schema_grant"


def _one(cur: Any) -> tuple[Any, ...]:
    row = cur.fetchone()
    assert row is not None
    return row  # type: ignore[no-any-return]


def _cfg(owner_sa: str) -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", owner_sa)
    return cfg


def _users_posture(owner_libpq: str) -> dict[str, Any]:
    with psycopg.connect(owner_libpq) as c:
        rls = _one(
            c.execute(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname='users'"
            )
        )
        grants = sorted(
            r[0]
            for r in c.execute(
                "SELECT privilege_type FROM information_schema.role_table_grants "
                "WHERE table_name='users' AND grantee='nlw_app'"
            ).fetchall()
        )
        fn = _one(c.execute("SELECT count(*) FROM pg_proc WHERE proname='resolve_or_create_user'"))[
            0
        ]
    return {"rls": rls, "app_grants": grants, "bootstrap_fn": fn}


def test_reversibility_matrix(pg_stack: SimpleNamespace) -> None:
    cfg = _cfg(pg_stack.owner_sa)

    # pg_stack already applied head. Verify the P1A posture.
    at_head = _users_posture(pg_stack.owner_libpq)
    assert at_head["rls"] == (True, True)
    assert at_head["app_grants"] == ["SELECT"]
    assert at_head["bootstrap_fn"] == 1

    # head -> previous: restores the pre-P1A posture exactly.
    command.downgrade(cfg, _PREV)
    at_prev = _users_posture(pg_stack.owner_libpq)
    assert at_prev["rls"] == (False, False)
    assert at_prev["app_grants"] == ["INSERT", "SELECT", "UPDATE"]
    assert at_prev["bootstrap_fn"] == 0

    # previous -> head again.
    command.upgrade(cfg, _HEAD)
    assert _users_posture(pg_stack.owner_libpq)["rls"] == (True, True)

    # head -> base -> head: the whole chain is reversible.
    command.downgrade(cfg, "base")
    with psycopg.connect(pg_stack.owner_libpq) as c:
        tables = _one(
            c.execute(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema='public' AND table_name IN ('users','connectors')"
            )
        )[0]
    assert tables == 0  # base leaves no app tables

    command.upgrade(cfg, _HEAD)
    final = _users_posture(pg_stack.owner_libpq)
    assert final["rls"] == (True, True)
    assert final["app_grants"] == ["SELECT"]
    assert final["bootstrap_fn"] == 1


def test_connectors_insert_policy_flips_with_migration(pg_stack: SimpleNamespace) -> None:
    cfg = _cfg(pg_stack.owner_sa)

    def _insert_check() -> str:
        with psycopg.connect(pg_stack.owner_libpq) as c:
            return str(
                _one(
                    c.execute(
                        "SELECT with_check FROM pg_policies "
                        "WHERE tablename='connectors' AND policyname='connectors_app_insert'"
                    )
                )[0]
            )

    # At head: admin/owner required.
    assert "is_current_user_admin_or_owner" in _insert_check()
    # Downgrade restores the member-level check.
    command.downgrade(cfg, _PREV)
    assert "is_current_user_member" in _insert_check()
    # Re-upgrade restores the admin/owner boundary.
    command.upgrade(cfg, _HEAD)
    assert "is_current_user_admin_or_owner" in _insert_check()
