# Single image for every application role (api / worker / scheduler).
# The role is selected at run time via the container command; the artifact is
# identical across roles and environments.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

# procps provides pgrep for the worker/scheduler container healthchecks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends procps \
    && rm -rf /var/lib/apt/lists/*

# uv provides fast, reproducible installs from the committed lockfile.
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

WORKDIR /app

# 1) Dependency layer (cached until pyproject/lock change).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# 2) Application layer.
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
RUN uv sync --frozen --no-dev

# Run as a non-root user (M9 hardening). Create it after the build steps (which
# need to write /app/.venv) and hand it ownership of the app tree.
RUN useradd --system --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Liveness without extra packages (slim image has no curl).
HEALTHCHECK --interval=10s --timeout=3s --retries=5 --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"

# Default role: API. Overridden by compose for worker/scheduler (M1b).
CMD ["python", "-m", "nlw.api"]
