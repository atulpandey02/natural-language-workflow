# Single image for every application role (api / worker / scheduler).
# The role is selected at run time via the container command; the artifact is
# identical across roles and environments.

FROM python:3.12-slim AS base

# Release identity baked into the artifact (M12A-Prep): CI passes the exact git
# SHA it built; the rollout's capability preflight reads it back from the image
# (`python -m nlw.ops.rollout.image_info`) and from the OCI revision label and
# refuses any image whose SHA differs from the release manifest.
ARG NLW_GIT_SHA=unknown
ENV NLW_GIT_SHA=${NLW_GIT_SHA}
LABEL org.opencontainers.image.revision=${NLW_GIT_SHA}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

# procps provides pgrep for the worker/scheduler container healthchecks.
# ca-certificates provides the system CA trust store at
# /etc/ssl/certs/ca-certificates.crt, required by the postgres connector's
# production TLS posture (sslmode=verify-full + sslrootcert=system) so a managed
# PostgreSQL provider's publicly-rooted certificate is trusted (M11.5 P1B).
RUN apt-get update \
    && apt-get install -y --no-install-recommends procps ca-certificates \
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
