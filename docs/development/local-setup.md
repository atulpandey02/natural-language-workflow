# Local development

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (`brew install uv`)
- Docker (for `docker compose` and integration tests)

Python 3.12 is installed automatically by uv (pinned in `.python-version`).

## Setup

```bash
uv sync                 # create .venv, install project + dev tools
cp .env.example .env    # optional; defaults work for local
```

## Everyday checks

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest -m "not integration"   # fast; no Docker needed
uv run pytest -m integration         # spins Postgres via testcontainers
```

## Running the stack

```bash
docker compose up -d --build         # api + postgres + redis (M1a)
curl localhost:8000/health           # {"status":"ok"}
curl localhost:8000/health/ready     # checks Postgres
curl localhost:8000/version
```

Apply migrations against the running database:

```bash
docker compose run --rm \
  -e DATABASE_URL=postgresql+psycopg://nlw:nlw@postgres:5432/nlw \
  api alembic upgrade head
```

Tear down:

```bash
docker compose down          # keep data
docker compose down -v       # also drop the postgres volume
```

## Notes

- The worker and scheduler services arrive in M1b to complete the five-service
  topology.
- Configuration is read once, from the environment, by `nlw.core.config.Settings`.
