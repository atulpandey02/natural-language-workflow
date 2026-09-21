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


# --- P1B: lexical-scope table resolution (defect #1, CTE-name collision) ---


def test_schema_qualified_table_sharing_cte_name_is_still_checked() -> None:
    # The CTE `secret_table` must NOT exempt the physical `private.secret_table`.
    _bad(
        "WITH secret_table AS (SELECT 1) SELECT * FROM private.secret_table",
        tables=["public.allowed"],
    )


def test_schema_qualified_allowed_named_cte_collision_is_checked() -> None:
    # A CTE named `allowed` must not exempt the physical `private.allowed`.
    _bad(
        "WITH allowed AS (SELECT 1) SELECT * FROM private.allowed",
        tables=["public.allowed"],
    )


def test_genuine_cte_reference_is_exempt() -> None:
    assert _ok("WITH recent AS (SELECT id FROM public.users) SELECT * FROM recent")


def test_nested_cte_resolves_in_scope() -> None:
    assert _ok(
        "WITH x AS (SELECT id FROM public.users) "
        "SELECT * FROM (WITH y AS (SELECT id FROM x) SELECT * FROM y) q"
    )


def test_shadowed_cte_name_resolves_correctly() -> None:
    # Inner `x` shadows outer `x`; both are CTE references, neither physical.
    assert _ok("WITH x AS (SELECT 1) SELECT * FROM (WITH x AS (SELECT 2) SELECT * FROM x) q")


def test_quoted_cte_identifier_resolves() -> None:
    assert _ok('WITH "Recent" AS (SELECT id FROM public.users) SELECT * FROM "Recent"')


def test_alias_matching_allowed_table_is_not_a_physical_table() -> None:
    # `users` here is a table alias, not a second physical table.
    assert _ok("SELECT users.id FROM public.orders AS users", tables=["public.orders"])


def test_unauthorized_table_inside_subquery_is_rejected() -> None:
    _bad("SELECT * FROM (SELECT * FROM private.secret) s")


def test_unauthorized_table_inside_cte_body_is_rejected() -> None:
    _bad("WITH bad AS (SELECT * FROM private.secret) SELECT * FROM bad")


def test_recursive_cte_is_supported_and_still_checks_physical_tables() -> None:
    assert _ok(
        "WITH RECURSIVE t AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM t WHERE n<5) SELECT * FROM t"
    )
    # A disallowed physical table in the recursive base is still rejected.
    _bad(
        "WITH RECURSIVE t AS (SELECT id AS n FROM private.secret "
        "UNION ALL SELECT n+1 FROM t WHERE n<5) SELECT * FROM t"
    )


def test_table_valued_function_is_not_treated_as_an_allowed_table() -> None:
    _bad("SELECT * FROM generate_series(1, 10) AS g")


# --- P1B: default-deny function allowlist (defect #2) ---


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT count(*) FROM public.users",
        "SELECT sum(id), avg(id), min(id), max(id) FROM public.users",
        "SELECT coalesce(name, 'x'), nullif(name, '') FROM public.users",
        "SELECT date_trunc('day', created_at), extract(year FROM created_at) FROM public.orders",
        "SELECT now(), current_date FROM public.users",
        "SELECT lower(name), upper(name), length(name), trim(name) FROM public.users",
        "SELECT abs(id), round(id, 2) FROM public.users",
        "SELECT id::text, id::integer FROM public.users",
    ],
)
def test_allows_allowlisted_functions(sql: str) -> None:
    assert _ok(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT myfunc() FROM public.users",  # unknown unqualified UDF
        "SELECT private.read_secret() FROM public.users",  # schema-qualified
        'SELECT "read_secret"() FROM public.users',  # quoted function identifier
        "SELECT pg_catalog.pg_read_file('x')",  # schema-qualified builtin
        "SELECT version()",  # unlisted builtin
        "SELECT string_agg(name, ',') FROM public.users",  # unlisted aggregate
        "SELECT count(private.read_secret()) FROM public.users",  # unapproved nested under allowed
        "SELECT 'x'::regclass FROM public.users",  # regclass cast (catalog coercion)
        "SELECT id::oid FROM public.users",  # oid cast
    ],
)
def test_rejects_non_allowlisted_functions(sql: str) -> None:
    _bad(sql)


def test_allowed_aggregate_nested_in_allowed_expression() -> None:
    assert _ok("SELECT coalesce(max(id), 0) FROM public.users")


def test_unapproved_function_inside_cte_or_subquery_is_rejected() -> None:
    _bad("WITH x AS (SELECT pg_sleep(1)) SELECT * FROM x")
    _bad("SELECT * FROM (SELECT dblink('h', 'q') AS d) s")


# --- Single authoritative validator (planning == runtime) ---


def test_planner_and_runtime_share_the_single_validator() -> None:
    # No separate planning/execution allowlists that could drift: feasibility and
    # the runtime tool both reference the exact same validate_select object.
    from nlw.feasibility import engine as feasibility_engine
    from nlw.feasibility import sql_safety
    from nlw.tools import postgres_tools

    assert vars(feasibility_engine)["validate_select"] is sql_safety.validate_select
    assert vars(postgres_tools)["validate_select"] is sql_safety.validate_select


# --- Parse failures ---


def test_rejects_garbage() -> None:
    _bad("this is not sql at all !!!")


def test_rejects_empty() -> None:
    _bad("   ")


# --- P1B addendum: SQL analysis fails closed ---


def test_parse_failure_is_a_stable_rejection() -> None:
    _bad("SELECT * FROM (")  # malformed -> could not parse


def test_build_scope_none_falls_back_to_full_physical_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nlw.feasibility import sql_safety

    monkeypatch.setattr(sql_safety, "build_scope", lambda *_a, **_k: None)
    # No scope -> nothing exempted -> a disallowed table is still rejected,
    # and a genuine CTE (which relied on scope) is now treated as physical
    # (unqualified) and rejected. Never accepted-by-fallback.
    _bad("SELECT * FROM private.secret")
    _bad("WITH x AS (SELECT 1) SELECT * FROM x")
    # An allowlisted schema-qualified table still validates.
    assert _ok("SELECT id FROM public.users")


def test_build_scope_exception_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from nlw.feasibility import sql_safety

    def _boom(*_a: object, **_k: object) -> object:
        raise RuntimeError("scope construction failure")

    monkeypatch.setattr(sql_safety, "build_scope", _boom)
    with pytest.raises(SqlSafetyError):
        validate_select("SELECT id FROM public.users", SCHEMAS, None)


def test_scope_traversal_exception_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from nlw.feasibility import sql_safety

    class _BadScope:
        def traverse(self) -> object:
            raise RuntimeError("traverse failure")

    monkeypatch.setattr(sql_safety, "build_scope", lambda *_a, **_k: _BadScope())
    with pytest.raises(SqlSafetyError):
        validate_select("SELECT id FROM public.users", SCHEMAS, None)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM json_to_recordset('[]') AS x(a int)",  # record-returning TVF
        "SELECT * FROM unnest(ARRAY[1,2,3]) AS u",  # set-returning function
        "SELECT * FROM jsonb_array_elements('[]'::jsonb) AS e",  # TVF + jsonb cast ok, fn not
    ],
)
def test_unsupported_table_valued_constructs_are_rejected(sql: str) -> None:
    _bad(sql)
