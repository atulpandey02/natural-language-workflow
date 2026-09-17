# ADR-000 — Engineering toolchain

- Status: Accepted
- Date: 2026-09-16

## Context

Greenfield, production-intended, self-hostable multi-tenant workflow platform,
built by a small team, targeting ~5 concurrent users on a single VPS initially
while preserving boundaries for later horizontal scaling. We need a minimal,
reproducible toolchain that supports strict correctness in the safety-critical
(deterministic) code paths without adding operational weight we do not yet need.

## Decision

Adopt the following toolchain. Items marked (M1+) are decided now but introduced
in later milestones with the components that need them.

- **Language:** Python 3.12 (`src/` layout, package `nlw`).
- **Packaging / env:** `uv` — single lockfile, fast, reproducible; manages the
  Python version too.
- **Format + lint:** `Ruff` (replaces black + isort + flake8).
- **Type checking:** `mypy`. **Strict** on `nlw.domain`, `nlw.feasibility`,
  `nlw.engine` (the invariant-heavy modules); standard elsewhere.
- **Testing:** `pytest`; `testcontainers` for integration tests (M1+).
- **Migrations:** `Alembic` (M1+). All schema changes are version-controlled.
- **Queue:** `Dramatiq` over Redis (M1+). Queue is **transport only**; durable
  state lives in Postgres, keeping the queue swappable.
- **Auth:** Supabase Auth (GoTrue) for identity, behind an `AuthProvider`
  abstraction; tenant membership and roles live in our own Postgres, not the
  provider (M2+).
- **LLM:** `LLMProvider` abstraction, Anthropic first; BYOK-ready (M6+).
- **CI:** GitHub Actions. **Registry:** GitHub Container Registry (ghcr.io).
- **Observability:** `structlog` + OpenTelemetry from early on; Langfuse for AI
  traces later. Postgres remains the system of record.
- **Frontend:** Vite + React + TypeScript, deferred to M10.

## Alternatives considered

- **Packaging:** Poetry / pip-tools / raw pip+venv — slower, more moving parts;
  `uv` unifies resolve/lock/run and Python management.
- **Format/lint:** black + isort + flake8 — three tools where Ruff is one.
- **Queue:** Celery (powerful but heavy ops for our scale) and RQ (weaker retry
  / middleware story). Dramatiq is the middle ground; low switching cost anyway
  because state is not in the queue.
- **Auth:** Clerk / Auth0 — better hosted DX but weaker self-hosting story and
  more lock-in; Supabase Auth is open-source and self-hostable, matching the
  product's self-hostable requirement.
- **Type checker:** pyright/ty — fine, but mypy is mature and adequate; revisit
  if performance becomes a problem.

## Consequences

- Fast, reproducible local and CI environments; a single, small tool surface.
- Strict typing concentrated where correctness matters most, without forcing it
  everywhere.
- Queue and auth are deliberately behind boundaries (transport-only queue;
  `AuthProvider` interface), so they can be replaced without rewrites.
- We introduce Docker, Alembic, Dramatiq, and Supabase in later milestones; this
  ADR fixes the choices so those milestones don't re-litigate them.
