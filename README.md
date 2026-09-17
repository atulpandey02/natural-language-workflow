# Natural Language Workflow Platform

A production-deployed, self-hostable AI workflow platform. Users describe a
workflow in natural language; an LLM converts it into a **structured plan**;
deterministic code validates and executes it durably, with multi-tenant
isolation and full auditability.

> **Core principle:** _Models reason. Code enforces invariants._ The LLM
> proposes plans and summarizes; it never controls authentication, tenant
> authorization, state transitions, retries, idempotency, SQL safety, secrets,
> or scheduling.

## Status

Pre-alpha. See [`docs/PROJECT_INDEX.md`](docs/PROJECT_INDEX.md) for the current
phase, milestones, and open risks. This repository is being built milestone by
milestone; nothing is deployed yet.

## Target architecture (V1)

```
Internet → HTTPS/reverse proxy → FastAPI (control plane)
                                    │
                        ┌───────────┴───────────┐
                        ▼                        ▼
                    PostgreSQL              Redis (queue transport)
                  (system of record)             │
                                                  ▼
                                    Workers (durable executor)
                                    Scheduler (due → enqueue)
```

State of record lives in **PostgreSQL**. Redis is transport only — losing it
loses no workflow. Application containers (`api`, `worker`, `scheduler`) are
stateless and built from one image.

## Development quickstart

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12 (uv can install it).

```bash
uv sync                       # create venv, install project + dev tools
uv run ruff format --check .  # formatting
uv run ruff check .           # lint
uv run mypy                   # type check
uv run pytest                 # tests
```

## Repository layout

```
src/nlw/        application package (see src/nlw/__init__.py for the module map)
tests/          unit + (later) integration tests
docs/           architecture, ADRs, runbooks, incidents, security, development
```

## Documentation

- [`CLAUDE.md`](CLAUDE.md) — persistent instructions for Claude Code sessions
- [`AGENTS.md`](AGENTS.md) — repo-wide expectations for coding agents
- [`docs/PROJECT_INDEX.md`](docs/PROJECT_INDEX.md) — project navigation & status
- [`docs/adr/`](docs/adr/) — architecture decision records
