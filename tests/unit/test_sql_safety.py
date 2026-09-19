"""Deterministic SQL safety matrix (M5, ADR-009).

Layer 1 of the three-layer read-only defense. These are pure unit tests: no DB.
They prove the validator accepts only single read-only queries over allowlisted,
schema-qualified physical tables and re-renders a canonical statement.
"""

import pytest

from nlw.feasibility.sql_safety import (
    SqlSafetyError,
    normalize_allowed_tables,
    validate_select,
)

SCHEMAS = ["public", "analytics"]


def _ok(sql: str, schemas: list[str] = SCHEMAS, tables: list[str] | None = None) -> str:
    return validate_select(sql, schemas, tables)


def _bad(sql: str, schemas: list[str] = SCHEMAS, tables: list[str] | None = None) -> None:
    with pytest.raises(SqlSafetyError):
        validate_select(sql, schemas, tables)


# --- Accepted read-only shapes ---


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id, name FROM public.users WHERE id = 1",
        "SELECT * FROM public.users u JOIN public.orders o ON o.user_id = u.id",
        "SELECT count(*) FROM analytics.events",
        "SELECT id FROM public.users UNION SELECT id FROM public.admins",
        "SELECT id FROM public.a INTERSECT SELECT id FROM public.b",
        "SELECT id FROM public.a EXCEPT SELECT id FROM public.b",
        "SELECT max(created_at) FROM public.orders GROUP BY user_id HAVING count(*) > 2",
        "SELECT id FROM public.users ORDER BY id LIMIT 10 OFFSET 5",
    ],
)
def test_accepts_read_only_queries(sql: str) -> None:
    rendered = _ok(sql)
    assert rendered.lower().startswith(("select", "with", "(")) or "select" in rendered.lower()


def test_cte_reference_not_treated_as_physical_table() -> None:
    sql = (
        "WITH recent AS (SELECT id FROM public.orders WHERE created_at > now()) "
        "SELECT * FROM recent"
    )
    rendered = _ok(sql)
    assert "recent" in rendered.lower()


def test_returns_canonical_rerendered_sql() -> None:
    # Comments / odd whitespace must not survive the round-trip.
    rendered = _ok("SELECT  id  /* c */  FROM   public.users  -- trailing\n")
    assert "/*" not in rendered and "--" not in rendered


# --- Non-SELECT statements ---


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO public.users (id) VALUES (1)",
        "UPDATE public.users SET name = 'x' WHERE id = 1",
        "DELETE FROM public.users WHERE id = 1",
        "DROP TABLE public.users",
        "ALTER TABLE public.users ADD COLUMN x int",
        "CREATE TABLE public.t (id int)",
        "TRUNCATE public.users",
        "GRANT SELECT ON public.users TO nlw_app",
        "SET statement_timeout = 0",
        "COPY public.users TO '/tmp/x.csv'",
        "MERGE INTO public.t USING public.s ON t.id = s.id WHEN MATCHED THEN DO NOTHING",
    ],
)
def test_rejects_non_select(sql: str) -> None:
    _bad(sql)


# --- Injection / multi-statement / locking / side effects ---


def test_rejects_multiple_statements() -> None:
    _bad("SELECT 1 FROM public.users; DROP TABLE public.users")


def test_rejects_stacked_write_after_select() -> None:
    _bad("SELECT id FROM public.users; DELETE FROM public.users")


def test_rejects_for_update() -> None:
    _bad("SELECT id FROM public.users FOR UPDATE")


def test_rejects_for_share() -> None:
    _bad("SELECT id FROM public.users FOR SHARE")


def test_rejects_select_into() -> None:
    _bad("SELECT id INTO public.copy FROM public.users")


def test_rejects_cte_with_data_modifying_statement() -> None:
    _bad(
        "WITH w AS (DELETE FROM public.users RETURNING id) SELECT * FROM w",
    )


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT pg_sleep(10)",
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT * FROM public.users WHERE id = lo_import('/etc/passwd')",
        "SELECT nextval('public.seq')",
        "SELECT setval('public.seq', 1)",
        "SELECT dblink('host=evil', 'SELECT 1')",
        "SELECT set_config('x', 'y', false)",
    ],
)
def test_rejects_dangerous_functions(sql: str) -> None:
    _bad(sql)


# --- Schema / table allowlisting ---


def test_rejects_unqualified_physical_table() -> None:
    # An unqualified name is NOT assumed to mean public.
    _bad("SELECT id FROM users")


def test_rejects_schema_not_in_allowlist() -> None:
    _bad("SELECT id FROM secret.credentials")


def test_rejects_information_schema_and_catalogs() -> None:
    _bad("SELECT * FROM information_schema.tables")
    _bad("SELECT * FROM pg_catalog.pg_user")


def test_table_allowlist_enforced_when_present() -> None:
    tables = ["public.users"]
    assert validate_select("SELECT id FROM public.users", SCHEMAS, tables)
    _bad("SELECT id FROM public.orders", tables=tables)


def test_table_allowlist_is_schema_qualified() -> None:
    # A different schema with the same table name is not allowed.
    _bad("SELECT id FROM analytics.users", tables=["public.users"])


# --- normalize_allowed_tables ---


def test_normalize_allowed_tables_lowercases() -> None:
    assert normalize_allowed_tables(["Public.Users"]) == {"public.users"}


def test_normalize_allowed_tables_none() -> None:
    assert normalize_allowed_tables(None) is None


@pytest.mark.parametrize("bad", ["users", "public.users.extra", "public.", ".users", ""])
def test_normalize_allowed_tables_rejects_bad_entries(bad: str) -> None:
    with pytest.raises(SqlSafetyError):
        normalize_allowed_tables([bad])


# --- Parse failures ---


def test_rejects_garbage() -> None:
    _bad("this is not sql at all !!!")


def test_rejects_empty() -> None:
    _bad("   ")
