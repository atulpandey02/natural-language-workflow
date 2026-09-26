"""Enqueue -> Redis -> worker execution, proven against a real Redis.

Starts a throwaway Redis (testcontainers), launches a real Dramatiq worker
subprocess pointed at it, enqueues a ``ping`` message, and asserts the worker
wrote its marker. Enqueuing uses an explicit broker bound to the container so
the test does not depend on module import order.
"""

import os
import subprocess
import sys
import time
import uuid
from types import SimpleNamespace

import pytest
import redis
from testcontainers.community.redis import RedisContainer

from nlw.core.config import Settings
from nlw.worker.actors import ping
from nlw.worker.broker import make_broker

pytestmark = pytest.mark.integration


def test_enqueue_ping_is_processed_by_worker(pg_stack: SimpleNamespace) -> None:
    # The worker's mandatory boot preflight reads the DR recovery lock, so a real
    # (never-restored) database is required for the worker to boot at all: with no
    # reachable database the state is UNKNOWN and boot is refused (fail closed).
    with RedisContainer("redis:7") as container:
        url = f"redis://{container.get_container_host_ip()}:{container.get_exposed_port(6379)}/0"

        worker = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "dramatiq",
                "nlw.worker.actors",
                "--processes",
                "1",
                "--threads",
                "1",
            ],
            env={
                **os.environ,
                "REDIS_URL": url,
                "DATABASE_URL": pg_stack.worker_settings.database_url,
                "APP_ENV": "local",
                "METRICS_ENABLED": "false",
            },
        )
        try:
            broker = make_broker(Settings(_env_file=None, redis_url=url))  # type: ignore[call-arg]
            broker.declare_queue("default")
            token = uuid.uuid4().hex
            broker.enqueue(ping.message(token))

            client = redis.from_url(url)
            deadline = time.time() + 20
            value = None
            while time.time() < deadline:
                value = client.get(f"nlw:ping:{token}")
                if value is not None:
                    break
                time.sleep(0.2)
            client.close()

            assert value == b"ok", "worker did not process the enqueued ping in time"
        finally:
            worker.terminate()
            worker.wait(timeout=10)
