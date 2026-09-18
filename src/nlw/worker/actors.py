"""Worker actors and the global broker configuration.

The worker entrypoint is ``dramatiq nlw.worker.actors``: importing this module
configures the global broker from settings and registers every actor.

M1b ships a single trivial ``ping`` actor that proves the enqueue -> Redis ->
worker path. It writes a short-lived Redis marker purely as a demonstration
signal; it is **not** workflow state. The real actor in later milestones will be
``advance_run(run_id)`` and will load authoritative state from Postgres.
"""

import dramatiq
import redis
import structlog

from nlw.core.config import get_settings
from nlw.worker.broker import make_broker

log = structlog.get_logger(__name__)

# Configure the global broker so actors below bind to it. The worker process and
# any enqueuing process read REDIS_URL from the environment via get_settings().
dramatiq.set_broker(make_broker(get_settings()))

# Marker TTL: the demonstration signal is ephemeral by design.
_PING_MARKER_TTL_SECONDS = 60


@dramatiq.actor
def ping(token: str) -> None:
    """Log receipt and write an ephemeral Redis marker keyed by ``token``."""
    log.info("worker.ping", token=token)
    client = redis.from_url(get_settings().redis_url)
    try:
        client.set(f"nlw:ping:{token}", "ok", ex=_PING_MARKER_TTL_SECONDS)
    finally:
        client.close()
