# CLAUDE.md — persistent project instructions

Instructions for Claude Code sessions on this repository. Keep this file short;
link to `docs/` rather than duplicating it.

## What this project is

A production, self-hostable natural-language workflow platform. See
[`README.md`](README.md) and [`docs/PROJECT_INDEX.md`](docs/PROJECT_INDEX.md).
Always read `docs/PROJECT_INDEX.md` first to learn the current phase and
milestone.

## Non-negotiable architectural invariants

- **Models reason; code enforces invariants.** The LLM may interpret language,
  generate structured plans, and summarize. It must **never** control:
  authentication, tenant authorization, permission enforcement, workflow state
  transitions, retry policy, idempotency, SQL safety, secret access, scheduler
  correctness, deterministic conditions, connector ownership, or
  destructive-action permissions.
- **Never execute LLM-generated code.** Only registered tools run. An unknown
  tool must fail feasibility.
- **Tenant isolation is enforced in the database and application layer**, never
  by the model. Every business resource is `tenant_id`-scoped; `tenant_id`
  propagates through the execution context.
- **Postgres is the system of record.** Redis is queue transport only; losing
  it must lose no workflow state.
- **Secrets are never placed in prompts, logs, or traces.** DB rows store
  credential references resolved via the `SecretStore` at execution time.
- **Feasibility is deterministic Python.** The LLM never approves its own plan.

## How to work here

- Work on **one issue/milestone at a time.** State the branch name before
  starting; explain intended changes before editing; avoid unrelated refactors.
- Branches: `feat/…`, `fix/…`, `test/…`, `docs/…`, `chore/…`. Trunk-based,
  short-lived. Keep `main` deployable.
- Commits: Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`),
  small and meaningful.
- **Write tests with the feature** and run them. Show failures honestly; never
  bypass tests to make CI green.
- **Do not silently add dependencies or change architecture.** New dependency or
  architectural decision ⇒ discuss, and record an ADR in `docs/adr/`.
- Update `docs/PROJECT_INDEX.md` after meaningful milestones; update docs when
  architecture changes.
- Ask before destructive operations. Never commit secrets.
- Keep deterministic safety logic separate from LLM logic. Prefer simple,
  readable code over clever abstractions.
- Never claim a feature is production-ready unless its tests and operational
  requirements actually support that claim.

## Checks to run before opening a PR

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

## Toolchain (see docs/adr/ADR-000-toolchain.md)

Python 3.12 · uv · Ruff · mypy (strict on `domain`/`feasibility`/`engine`) ·
pytest · Alembic (M1+) · Dramatiq/Redis (M1+) · Supabase Auth behind an
`AuthProvider` abstraction (M2+) · GitHub Actions · ghcr.io · structlog + OTel.
