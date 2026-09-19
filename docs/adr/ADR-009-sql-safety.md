# ADR-009 — Deterministic SQL safety for read-only database access

- Status: Accepted
- Date: 2026-09-19

## Context

The first real data connector (`postgres`, M5) lets a workflow read a tenant's
external database. The SQL that reaches the driver must be provably read-only and
constrained to an allowlisted surface, and this guarantee must **not** depend on
the LLM. A single control is not enough: a parser bug, a novel injection, or a
mis-scoped role should each be insufficient on its own to cause a write or an
out-of-scope read.

## Decision

Three **independent** read-only controls, each sufficient to stop a write on its
own (defense in depth):

1. **Deterministic validation (`nlw.feasibility.sql_safety`, sqlglot).** The SQL
   is parsed with the `postgres` dialect and accepted only if it is *exactly one*
   statement of a read-only query kind (`SELECT`/`UNION`/`INTERSECT`/`EXCEPT`/
   `WITH`). Any DML/DDL/DCL/transaction/`SET`/`COPY` node anywhere in the tree,
   row-locking (`FOR UPDATE/SHARE`), `SELECT INTO`, data-modifying CTEs, and a
   denylist of side-effecting/catalog/file functions (`pg_sleep`, `pg_read_file`,
   `lo_import`, `dblink`, `setval`/`nextval`, …) are rejected. Every **physical**
   table must be schema-qualified (an unqualified name is *not* assumed to mean
   `public`), its schema must be in the connector's `allowed_schemas`, and — when
   `allowed_tables` is set — the `schema.table` must be allowlisted. CTE names are
   excluded from the physical-table check. The validator returns the
   **re-rendered** AST (comments stripped) so comment/whitespace tricks cannot
   survive to the driver.
2. **Read-only session/transaction.** Every connection is opened with
   `default_transaction_read_only=on`, plus `statement_timeout`, `lock_timeout`
   and `idle_in_transaction_session_timeout`. A write blocks even if layers 1 and
   3 were bypassed.
3. **SELECT-only external role.** Operators provision the credential as a role
   with only `SELECT` (and only on the intended tables). A write fails even inside
   a (hypothetically) writable session.

Validation is layer 1; ADR-012 covers layers 2–3 and the driver path. The LLM
never generates or executes SQL in M5 — it is authored deterministically and
validated here.

## Alternatives considered

- **Trust an ORM / parameterization only** — rejected: does not constrain
  statement *kind* or table surface, and does not stop stacked statements.
- **Regex/keyword denylist** — rejected: not robust to comments, casing,
  encodings, or nesting; a parser + allowlist is far harder to evade.
- **Rely on the read-only role alone** — rejected: a mis-provisioned role would
  be a single point of failure; the layers are intentionally redundant.
- **Allow unqualified tables defaulting to `public`** — rejected: ambiguous and
  `search_path`-dependent; we require explicit `schema.table`.

## Consequences

- Read-only access is enforced by deterministic Python and Postgres, never the
  model; each control is independently testable (see the M5 security matrix).
- Legitimate queries must be schema-qualified and stay within the allowlist —
  a small authoring constraint for a large safety gain.
- Bind parameters, `schema.inspect`, and write tools are out of scope here and
  slot into the same validator/driver seam later without weakening these rules.
