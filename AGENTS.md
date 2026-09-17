# AGENTS.md — repository expectations for coding agents

Applies to any automated coding agent working in this repository. It complements
[`CLAUDE.md`](CLAUDE.md) (which holds the architectural invariants) with concrete
conventions. When they overlap, `CLAUDE.md` wins.

## Conventions

- Language: Python 3.12, `src/` layout, package `nlw`.
- Formatting & lint: **Ruff** (`uv run ruff format`, `uv run ruff check`).
- Types: **mypy**. Strict in `nlw.domain`, `nlw.feasibility`, `nlw.engine`;
  standard elsewhere. New public functions get type annotations.
- Tests: **pytest** under `tests/` (`unit/`, later `integration/`).

## Definition of done for any change

1. Formatting, lint, type check, and tests pass locally:
   ```bash
   uv run ruff format --check . && uv run ruff check . && uv run mypy && uv run pytest
   ```
2. New behavior has tests. Invariants and boundaries are tested heavily
   (auth, tenant isolation, feasibility, SQL safety, durability, idempotency).
3. Docs updated when architecture changes; ADR added for architectural
   decisions; `docs/PROJECT_INDEX.md` updated after a milestone.
4. No secrets committed. No new dependency introduced silently.

## Scope discipline

- One issue/milestone per branch/PR. No opportunistic refactoring.
- State the branch name and intended changes before editing.
- Report outcomes honestly, including failures and skipped steps.
