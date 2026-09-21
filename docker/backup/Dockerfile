# Disaster-recovery backup/restore image (M11.5 P2).
#
# Extends the immutable application image (so the SAME nlw code + venv drive the
# backup/restore/quiesce/validate orchestrators) with the two extra tools the data
# path needs: the PostgreSQL 16 client (pg_dump/pg_restore/pg_dumpall/psql) and
# restic (client-side-encrypted, S3-compatible backups). NOTHING here is a runtime
# service — it runs one-shot under a dedicated Compose profile.
#
# Build (after building the app image as ${NLW_IMAGE}):
#   docker build -t nlw-backup:local -f docker/backup/Dockerfile \
#       --build-arg NLW_IMAGE=nlw:local .

ARG NLW_IMAGE=nlw:local
FROM ${NLW_IMAGE}

USER root

# PostgreSQL 16 client (must be >= the server version to dump PG16) from the
# official PGDG apt repo, plus restic. ca-certificates already present in base.
# The PGDG suite MUST match the base image's Debian release (bookworm vs trixie),
# so derive it from /etc/os-release rather than hardcoding a codename — a pinned
# codename that drifts from the base image pulls an unsatisfiable libpq5/libldap.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends gnupg wget restic; \
    . /etc/os-release; \
    install -d /usr/share/postgresql-common/pgdg; \
    wget -qO /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc; \
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
http://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends postgresql-client-16; \
    apt-get purge -y --auto-remove gnupg wget; \
    rm -rf /var/lib/apt/lists/*

# restic + transient dumps live on a tmpfs mount; HOME must be writable.
ENV RESTIC_CACHE_DIR=/tmp/restic-cache \
    HOME=/tmp \
    NLW_BACKUP_WORK_DIR=/tmp/nlw-backup \
    NLW_RESTORE_WORK_DIR=/tmp/nlw-restore

WORKDIR /app

# `nlw.backup` dispatches: backup | restore | quiesce | validate.
ENTRYPOINT ["python", "-m", "nlw.backup"]
CMD ["backup"]
