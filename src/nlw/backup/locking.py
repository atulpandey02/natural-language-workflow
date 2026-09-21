"""Single-execution host/process lock for the backup lifecycle (M11.5 P2 addendum A).

The systemd timer, `Type=oneshot`, and restic's repository lock are NOT sufficient
proof that two backup *processes* cannot overlap: a manual invocation, a duplicate
timer, or an orchestration error can launch a second process. restic's lock only
guards the repository during its own operation — it does not cover config
validation, the plaintext dump, the manifest, or the metrics write, and it does not
stop a second `pg_dump` from running.

So we take an explicit, advisory `flock` around the ENTIRE lifecycle
(config -> dump -> manifest -> restic backup -> verify -> retention -> metrics),
acquired BEFORE any dump/temp artifact is created and released on success, failure,
signal, and process death (the OS drops an advisory lock when the fd closes / the
process exits — so a leftover lock *file* never permanently blocks a later run when
no process actually holds the lock).

For two backup CONTAINERS to contend, the lock file must live on a shared, writable
runtime volume mounted into each (see the compose `backup_run` volume); within one
host/mount namespace, `flock` is honored across processes.
"""

import contextlib
import errno
import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class BackupAlreadyRunning(RuntimeError):
    """Raised (fast, non-zero exit) when another backup already holds the lock."""


@contextmanager
def backup_lock(lock_file: Path) -> Iterator[None]:
    """Acquire an exclusive, non-blocking advisory lock for the backup lifecycle.

    A second invocation fails fast with :class:`BackupAlreadyRunning` and never runs
    a dump, upload, prune, or metrics write. The lock file holds only this process's
    PID (no secret). The lock is released on normal exit AND on exception/signal via
    the ``finally`` closing the fd.
    """
    # 0600: the lock file is process metadata, readable only by the owner.
    fd = os.open(str(lock_file), os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                raise BackupAlreadyRunning(
                    "another backup is already running (lock held); refusing to start a "
                    "second concurrent backup"
                ) from None
            raise
        # We hold the lock. Record our PID (best-effort; never a secret).
        with contextlib.suppress(OSError):
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
            os.fsync(fd)
        yield
    finally:
        # Closing the fd releases the advisory lock even on signal/crash. We do NOT
        # unlink the file: unlinking races with a concurrent opener and is
        # unnecessary — advisory locks are keyed to the open fd, not the name.
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
