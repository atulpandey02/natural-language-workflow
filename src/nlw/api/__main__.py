"""Entrypoint for the API role: ``python -m nlw.api``."""

import uvicorn

from nlw.core.config import get_settings


def main() -> None:
    # Validate configuration eagerly so a misconfigured process fails fast.
    get_settings()
    # Bind all interfaces so the container is reachable; the reverse proxy sits
    # in front in every non-local environment.
    uvicorn.run(
        "nlw.api.app:create_app",
        factory=True,
        host="0.0.0.0",  # noqa: S104 - containerized service behind a proxy
        port=8000,
        log_config=None,  # structlog owns logging
    )


if __name__ == "__main__":
    main()
