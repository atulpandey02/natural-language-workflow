"""Deterministic SQL safety for read-only Postgres access (M5).

sqlglot-based. Accepts exactly one read-only query over allowlisted,
schema-qualified physical tables; rejects everything else. This is layer 1 of
three (see ADR-009); it never trusts the caller's SQL and re-renders the parsed
AST so comment/whitespace tricks cannot survive.
"""

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from nlw.registry.registry import ToolExecutionError


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

# Dangerous / side-effecting or catalog/file functions.
_DANGEROUS_FUNCTIONS = frozenset(
    {
        "pg_sleep",
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "pg_stat_file",
        "lo_import",
        "lo_export",
        "dblink",
        "dblink_exec",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "set_config",
        "pg_reload_conf",
        "setval",
        "nextval",
        "copy",
        "query_to_xml",
    }
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


def validate_select(sql: str, allowed_schemas: list[str], allowed_tables: list[str] | None) -> str:
    """Validate ``sql`` and return the canonical re-rendered SQL. Raises SqlSafetyError."""
    allowed_schema_set = {s.lower() for s in allowed_schemas}
    allowed_table_set = normalize_allowed_tables(allowed_tables)

    try:
        parsed = sqlglot.parse(sql, dialect="postgres")
    except SqlglotError as exc:
        raise SqlSafetyError("could not parse SQL") from exc

    statements = [s for s in parsed if s is not None]
    if len(statements) != 1:
        raise SqlSafetyError("exactly one statement is allowed")
    statement = statements[0]

    if not isinstance(statement, _QUERY_TYPES):
        raise SqlSafetyError("only SELECT queries are allowed")

    if next(iter(statement.find_all(*_FORBIDDEN_NODES)), None) is not None:
        raise SqlSafetyError("statement contains a forbidden (non read-only) operation")

    if next(iter(statement.find_all(exp.Lock)), None) is not None:
        raise SqlSafetyError("row-locking clauses (FOR UPDATE/SHARE) are not allowed")

    for select in statement.find_all(exp.Select):
        if select.args.get("into") is not None:
            raise SqlSafetyError("SELECT INTO is not allowed")

    for func in statement.find_all(exp.Anonymous):
        if func.name.lower() in _DANGEROUS_FUNCTIONS:
            raise SqlSafetyError(f"function not allowed: {func.name.lower()}")

    cte_names = {cte.alias.lower() for cte in statement.find_all(exp.CTE) if cte.alias}
    for table in statement.find_all(exp.Table):
        name = table.name
        if name.lower() in cte_names:
            continue  # a CTE reference, not a physical table
        schema = table.db
        if not schema:
            raise SqlSafetyError(f"physical tables must be schema-qualified: {name}")
        if schema.lower() not in allowed_schema_set:
            raise SqlSafetyError(f"schema not allowed: {schema}")
        if allowed_table_set is not None and f"{schema}.{name}".lower() not in allowed_table_set:
            raise SqlSafetyError(f"table not allowed: {schema}.{name}")

    # Strip comments in the canonical render so nothing but the validated AST
    # reaches the driver.
    return statement.sql(dialect="postgres", comments=False)
