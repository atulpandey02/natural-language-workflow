"""Regression control: platform SQL is never built by string interpolation (M9).

This is NOT a proof that SQL injection is impossible (ADR-003 M9 update). It is a
guard that keeps the "no untrusted SQL under platform DB roles" property true as
code changes: SQL passed to SQLAlchemy ``text(...)`` or to a ``.execute(...)``
call must never be an f-string, a ``%``/``+`` string concatenation, or a
``str.format(...)`` — always a constant with bound parameters.

The external ``postgres.query`` tool (a separate, sqlglot-validated surface that
runs against the *tenant's* database, not the platform DB) assigns its rendered
SQL to a variable before executing, so it is not an inline-interpolation site and
is not (and need not be) covered here.
"""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "nlw"


def _is_interpolated(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod | ast.Add):
        # "..." % x  or  "..." + x  where a side is a string literal
        for side in (node.left, node.right):
            if isinstance(side, ast.Constant) and isinstance(side.value, str):
                return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
    )


def _offending_sql_sites(path: Path) -> list[int]:
    tree = ast.parse(path.read_text())
    bad: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        name = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr
            if isinstance(func, ast.Attribute)
            else ""
        )
        if name in {"text", "execute"} and _is_interpolated(node.args[0]):
            bad.append(node.lineno)
    return bad


def test_no_interpolated_platform_sql() -> None:
    offenders: dict[str, list[int]] = {}
    for path in SRC.rglob("*.py"):
        lines = _offending_sql_sites(path)
        if lines:
            offenders[str(path.relative_to(SRC))] = lines
    assert offenders == {}, f"interpolated SQL found (use bound params): {offenders}"
