"""Isolated profiling process: ``python -m nlw.ingest.runner '<limits json>'``.

Reads CSV bytes from stdin, writes ONE JSON line to stdout and exits:

- ``{"status": "profiled", "profile": {...profile-2...}}``
- ``{"status": "rejected", "code": "<rejection code>"}``
- ``{"status": "failed"}`` (unexpected error: no message, no content)

The parent starts it with an empty environment (no database URL, storage or
signing material, no credentials), so the only thing this process can see is
the bytes it is given. Before reading, it caps its address space and CPU time
(where the OS supports it) and disables sockets. ``csv.field_size_limit`` is
process-global, which is one more reason the profiler runs here and not in the
API process. Nothing written to stdout or stderr contains a cell value.
"""

from __future__ import annotations

import contextlib
import json
import sys
from typing import Any, NoReturn


def _limit_resources(memory_mb: int, cpu_s: int) -> None:
    try:
        import resource
    except ImportError:  # pragma: no cover - non-POSIX
        return
    for name, value in (("RLIMIT_AS", memory_mb * 1024 * 1024), ("RLIMIT_CPU", cpu_s)):
        limit = getattr(resource, name, None)
        if limit is None:
            continue
        # e.g. macOS refuses RLIMIT_AS: the parent's wall clock still applies.
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(limit, (value, value))


def _disable_network() -> None:
    import socket

    def _refuse(*_args: Any, **_kwargs: Any) -> NoReturn:
        raise OSError("network access is disabled in the profiling process")

    socket.socket = _refuse  # type: ignore[assignment,misc]
    socket.create_connection = _refuse
    socket.getaddrinfo = _refuse


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    sys.stdout.write("\n")
    sys.stdout.flush()


def main(argv: list[str]) -> int:
    try:
        cfg = json.loads(argv[1])
        memory_mb = int(cfg.pop("memory_mb"))
        _limit_resources(memory_mb, int(cfg["timeout_s"]) + 5)
        _disable_network()
        from nlw.ingest.strict import PolicyReject, StrictLimits, profile_stream

        limits = StrictLimits(**cfg)
        try:
            profile = profile_stream(sys.stdin.buffer, limits)
        except PolicyReject as exc:
            _emit({"status": "rejected", "code": str(exc.code)})
            return 0
        _emit({"status": "profiled", "profile": json.loads(profile.model_dump_json())})
        return 0
    except MemoryError:
        _emit({"status": "rejected", "code": "PROCESSING_FAILED"})
        return 0
    except Exception:
        _emit({"status": "failed"})
        return 3


if __name__ == "__main__":  # pragma: no cover - exercised through a subprocess
    raise SystemExit(main(sys.argv))
