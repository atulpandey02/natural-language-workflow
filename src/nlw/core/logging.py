"""Structured logging setup (structlog).

Console-rendered in local development, JSON everywhere else so logs are
machine-parseable in staging/production. This is the observability spine that
later milestones enrich with request/run/tenant context.
"""

import logging

import structlog
from structlog.typing import Processor

from nlw.core.config import Settings


def configure_logging(settings: Settings) -> None:
    """Configure structlog + stdlib logging for the current process."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", level=level)

    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if settings.app_env == "local":
        processors.append(structlog.dev.ConsoleRenderer())
    else:
        processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
