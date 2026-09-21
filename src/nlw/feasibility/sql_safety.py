"""Deterministic SQL safety for read-only Postgres access (M5; hardened M11.5 P1B).

sqlglot-based. Accepts exactly one read-only query over allowlisted,
schema-qualified physical tables, using only an explicit allowlist of safe SQL
functions/forms. This is layer 1 of three (see ADR-009); it never trusts the
caller's SQL and re-renders the parsed AST so comment/whitespace tricks cannot
survive.

P1B hardening:
- Table authorization uses actual lexical scope (``sqlglot.optimizer.scope``),
  not name coincidence: a schema-qualified physical table is ALWAYS checked even
  if its unqualified name matches a CTE alias. Only a reference that actually
  resolves to an in-scope CTE/derived table is exempt.
- Functions are default-DENY: only an explicit allowlist of safe, deterministic,
  side-effect-free functions (mapped to typed sqlglot nodes) is permitted.
  Schema-qualified, user-defined, and unknown functions all parse to
  ``exp.Anonymous`` (or an unlisted typed node) and are rejected. Casts are
  restricted to a safe set of target types (no ``regclass``/catalog coercions).
"""

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.scope import Scope, build_scope

from nlw.registry.registry import ToolExecutionError

# Stable, inventory-safe rejection messages (see ADR-009 / P1B F2).
_ERR_PARSE = "could not parse SQL"
_ERR_ONE_STATEMENT = "exactly one statement is allowed"
_ERR_NOT_SELECT = "only SELECT queries are allowed"
_ERR_FORBIDDEN = "statement contains a forbidden (non read-only) operation"
_ERR_LOCK = "row-locking clauses (FOR UPDATE/SHARE) are not allowed"
_ERR_INTO = "SELECT INTO is not allowed"
_ERR_UNQUALIFIED = "physical tables must be schema-qualified"
_ERR_SCHEMA = "schema not allowed"
_ERR_TABLE = "table not allowed"
_ERR_FUNCTION = "sql function not allowed"
_ERR_CAST = "cast to an unsupported type is not allowed"


class SqlSafetyError(ToolExecutionError):
    """A SQL statement violates the read-only safety policy (deterministic)."""


# Top-level statement must be one of these query kinds.
_QUERY_TYPES: tuple[type[exp.Expression], ...] = (
    exp.Select,
    exp.Union,
    exp.Intersect,
    exp.Except,
    exp.With,
)

# Any occurrence anywhere in the tree of these is a hard rejection. exp.Command
# is sqlglot's catch-all for COPY/CALL/DO/GRANT/REVOKE/VACUUM/etc.
_FORBIDDEN_NODE_NAMES = (
    "Insert",
    "Update",
    "Delete",
    "Merge",
    "Drop",
    "Alter",
    "AlterTable",
    "Create",
    "TruncateTable",
    "Command",
    "Set",
    "SetItem",
    "Transaction",
    "Commit",
    "Rollback",
    "Grant",
    "Revoke",
    "Use",
    "Copy",
)
_FORBIDDEN_NODES: tuple[type[exp.Expression], ...] = tuple(
    getattr(exp, name) for name in _FORBIDDEN_NODE_NAMES if hasattr(exp, name)
)

# --- Function allowlist (default-DENY) ---------------------------------------
# Every entry is a safe, deterministic, side-effect-free function that sqlglot
# parses into a distinct typed node. Anything NOT here (incl. every
# exp.Anonymous — which is what schema-qualified / user-defined / unknown
# functions parse to — and any unlisted typed function such as generate_series,
# pg_read_file, dblink, pg_sleep, nextval, set_config, ...) is rejected.
_ALLOWED_FUNCTION_NODE_NAMES = (
    # aggregates
    "Count",
    "Sum",
    "Avg",
    "Min",
    "Max",
    # null handling
    "Coalesce",
    "Nullif",
    # date/time (read-only, deterministic within a statement)
    "TimestampTrunc",  # DATE_TRUNC
    "Extract",  # EXTRACT / date_part
    "CurrentTimestamp",  # now() / current_timestamp
    "CurrentDate",  # current_date
    # string
    "Lower",
    "Upper",
    "Length",
    "Trim",
    "Substring",
    "Concat",
    # numeric
    "Abs",
    "Round",
    "Ceil",
    "Floor",
)
_ALLOWED_FUNCTION_NODES: tuple[type[exp.Expression], ...] = tuple(
    getattr(exp, name) for name in _ALLOWED_FUNCTION_NODE_NAMES if hasattr(exp, name)
)

# Safe cast target types (by sqlglot DataType.Type). Reg*/OID/catalog coercions
# are excluded so a cast cannot trigger catalog lookups (e.g. ``::regclass``).
_ALLOWED_CAST_TYPES = frozenset(
    t
    for t in (
        getattr(exp.DataType.Type, name, None)
        for name in (
            "TEXT",
            "VARCHAR",
            "CHAR",
            "NCHAR",
            "NVARCHAR",
            "INT",
            "SMALLINT",
            "BIGINT",
            "TINYINT",
            "DECIMAL",
            "FLOAT",
            "DOUBLE",
            "BOOLEAN",
            "DATE",
            "TIME",
            "TIMESTAMP",
            "TIMESTAMPTZ",
            "INTERVAL",
            "UUID",
            "JSON",
            "JSONB",
            "VARBINARY",
        )
    )
    if t is not None
)


def normalize_allowed_tables(allowed_tables: list[str] | None) -> set[str] | None:
    """Canonicalize allowlist entries to lowercase ``schema.table``."""
    if allowed_tables is None:
        return None
    normalized: set[str] = set()
    for entry in allowed_tables:
        parts = entry.split(".")
        if len(parts) != 2 or not all(parts):
            raise SqlSafetyError(f"allowed_tables entry must be schema.table: {entry!r}")
        normalized.add(entry.lower())
    return normalized


def _validate_functions(statement: exp.Expression) -> None:
    """Default-deny: every function node must be in the allowlist."""
    for func in statement.find_all(exp.Func):
        if isinstance(func, exp.Cast):
            to = func.to
            if not isinstance(to, exp.DataType) or to.this not in _ALLOWED_CAST_TYPES:
                raise SqlSafetyError(_ERR_CAST)
            continue
        if isinstance(func, _ALLOWED_FUNCTION_NODES):
            continue
        # exp.Anonymous (schema-qualified / UDF / unknown) and any unlisted typed
        # function (generate_series, pg_read_file, dblink, ...) land here.
        raise SqlSafetyError(_ERR_FUNCTION)


def _cte_reference_node_ids(statement: exp.Expression) -> set[int]:
    """Ids of ``exp.Table`` nodes that actually resolve to an in-scope CTE or
    derived table (lexical scope), so they may skip physical-table checks.

    A CTE reference is never schema-qualified, so a table with a schema is always
    treated as physical regardless of any name coincidence with a CTE alias.
    """
    root = build_scope(statement)
    if root is None:
        return set()
    cte_ids: set[int] = set()
    for scope in root.traverse():
        for table in scope.tables:
            if table.db:
                continue  # schema-qualified -> always physical
            source = scope.sources.get(table.name)
            if isinstance(source, Scope):
                cte_ids.add(id(table))
    return cte_ids


def _validate_tables(
    statement: exp.Expression,
    allowed_schema_set: set[str],
    allowed_table_set: set[str] | None,
) -> None:
    cte_ids = _cte_reference_node_ids(statement)
    for table in statement.find_all(exp.Table):
        if id(table) in cte_ids:
            continue  # a genuine, in-scope CTE/derived reference
        name = table.name
        if not name:
            # A table-valued function (e.g. generate_series(...)) has no table
            # name; its function node is governed by the function allowlist.
            continue
        schema = table.db
        if not schema:
            raise SqlSafetyError(f"{_ERR_UNQUALIFIED}: {name}")
        if schema.lower() not in allowed_schema_set:
            raise SqlSafetyError(f"{_ERR_SCHEMA}: {schema}")
        if allowed_table_set is not None and f"{schema}.{name}".lower() not in allowed_table_set:
            raise SqlSafetyError(f"{_ERR_TABLE}: {schema}.{name}")


def validate_select(sql: str, allowed_schemas: list[str], allowed_tables: list[str] | None) -> str:
    """Validate ``sql`` and return the canonical re-rendered SQL. Raises SqlSafetyError.

    This is the single authoritative validator shared by planner feasibility,
    plan materialization/revalidation, and runtime execution.
    """
    allowed_schema_set = {s.lower() for s in allowed_schemas}
    allowed_table_set = normalize_allowed_tables(allowed_tables)

    try:
        parsed = sqlglot.parse(sql, dialect="postgres")
    except SqlglotError as exc:
        raise SqlSafetyError(_ERR_PARSE) from exc

    statements = [s for s in parsed if s is not None]
    if len(statements) != 1:
        raise SqlSafetyError(_ERR_ONE_STATEMENT)
    statement = statements[0]

    if not isinstance(statement, _QUERY_TYPES):
        raise SqlSafetyError(_ERR_NOT_SELECT)

    if next(iter(statement.find_all(*_FORBIDDEN_NODES)), None) is not None:
        raise SqlSafetyError(_ERR_FORBIDDEN)

    if next(iter(statement.find_all(exp.Lock)), None) is not None:
        raise SqlSafetyError(_ERR_LOCK)

    for select in statement.find_all(exp.Select):
        if select.args.get("into") is not None:
            raise SqlSafetyError(_ERR_INTO)

    _validate_functions(statement)
    _validate_tables(statement, allowed_schema_set, allowed_table_set)

    # Strip comments in the canonical render so nothing but the validated AST
    # reaches the driver.
    return statement.sql(dialect="postgres", comments=False)
