"""Entrypoint for the API role: ``python -m nlw.api``."""

import uvicorn

from nlw.core.config import get_settings
from nlw.observability.metrics import start_metrics_server


def main() -> None:
    # Validate configuration eagerly so a misconfigured process fails fast.
    settings = get_settings()
    # Prometheus metrics on a separate INTERNAL port (never the public API port).
    start_metrics_server(settings, role="api")
    # Only X-Forwarded-* from the configured reverse-proxy IPs are trusted; with
    # none configured we trust none (do not believe arbitrary forwarded headers).
    forwarded_allow_ips = ",".join(settings.trusted_proxy_ips)
    # Bind all interfaces so the container is reachable; the reverse proxy sits
    # in front in every non-local environment.
    uvicorn.run(
        "nlw.api.app:create_app",
        factory=True,
        host="0.0.0.0",  # noqa: S104 - containerized service behind a proxy
        port=8000,
        log_config=None,  # structlog owns logging
        proxy_headers=True,
        forwarded_allow_ips=forwarded_allow_ips,
    )


if __name__ == "__main__":
    main()
