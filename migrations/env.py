"""Alembic environment.

The database URL comes from application settings (never hard-coded here), and
the sync psycopg engine reuses the same ``postgresql+psycopg://`` URL as the
async application engine. ``target_metadata`` is ``Base.metadata`` so that
autogenerate sees every ORM model once they are imported below.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from nlw.core.config import get_settings
from nlw.db import models  # noqa: F401  (register models on Base.metadata)
from nlw.db.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Migrations run as the owner/migration role. Prefer an explicitly configured
# URL (tests set it directly), then the migration URL, then the runtime URL.
if not config.get_main_option("sqlalchemy.url"):
    settings = get_settings()
    config.set_main_option(
        "sqlalchemy.url", settings.database_migration_url or settings.database_url
    )

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DBAPI connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode against a live connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
