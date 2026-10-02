# Scheduler lagging / stopped

**Symptoms:** due runs not created on time; `nlw_scheduler_runs_created_total`
flat; reconcile not running.

**Do:**
1. Check the scheduler container + logs; confirm its metrics port is up.
2. Confirm it connects as `nlw_scheduler` and Postgres/Redis are reachable.
3. Restart it. Due-scan is idempotent (exactly one run row per occurrence via
   SKIP LOCKED + unique constraint), so restarts never double-create runs.
4. Bounded catch-up fires only the latest missed occurrence within the catch-up
   window; large gaps are intentionally not backfilled.

## Graceful shutdown (rollout `drain`, `docker compose stop`)

**Contract.** On SIGTERM (or SIGINT) the scheduler stops starting ticks. A tick
already in progress completes: it commits its run rows and then enqueues exactly
those runs (the existing commit-then-enqueue order), so shutdown neither
duplicates nor drops work. If the stop arrives during startup, no tick runs. The
database engine and the Redis broker are closed. On the demonstrated healthy
paths the process stops in well under a second, far inside Docker's 10 s grace
period: exit `0` when idle or after the current tick, and exit `143` when the
stop lands in the first moments of startup, before any work. Startup, or a tick
in progress, that is blocked on an external dependency (Postgres, Redis) is
bounded instead by that dependency's timeouts and, ultimately, by Docker's
SIGKILL at the end of the grace period (see Remaining limitations). Further stop
signals after the first are ignored, so they cannot interrupt cleanup. A hard kill
mid-tick (power loss, `docker kill -s KILL`) remains safe for the reasons above:
due-scan is idempotent and the reconciler re-enqueues stale `PENDING` runs.

**Why it was killed (`Exited (137)`) during the `10820a8` staging drain.** Two
defects, reproduced with the real image under production-shaped Compose
(`tests/drills/scheduler_shutdown_drill.sh`, 10 s grace, nothing in flight):

| Round | Before (`10820a8`) | After |
|---|---|---|
| Stop in steady state | 10.30 s, exit 137 | 0.35–0.43 s, exit 0 |
| Stop during startup | 10.29 s, exit 137 | 0.15–0.18 s, exit 143 (terminated before any work) |
| Repeated SIGTERM | still running after 10 s | 0.14–0.20 s, exit 0 |

1. *Steady state.* The handler only set a flag; the loop slept in
   `time.sleep(scheduler_scan_interval_s)` (30 s). Since PEP 475 Python resumes
   that sleep after a signal handler returns, so the flag was seen up to 30 s
   later, after Docker's 10 s grace period had sent SIGKILL. The log showed
   `scheduler.shutdown` and then nothing. `init: true` alone does not fix this
   (measured: still 10.31 s / 137).
2. *Startup.* The handler was installed only after initialization. The scheduler
   ran as PID 1, and the kernel discards a handler-less SIGTERM sent to PID 1, so a
   stop during startup was lost; the scheduler then started its loop and was
   SIGKILLed at the grace period.

**Fix.** `nlw.scheduler.__main__` installs the stop handlers first, and the loop
waits on a `threading.Event` (`Event.wait` returns as soon as the handler sets
it) instead of `time.sleep`. `docker-compose.prod.yml` runs the scheduler with
`init: true`, so Docker's init is PID 1 and forwards signals; a SIGTERM that lands
before Python has installed its handler then terminates it at once (exit 143)
instead of being discarded. `scheduler_scan_interval_s` and the grace period
are unchanged. API and worker are unchanged.

**Evidence.** `tests/unit/test_scheduler_shutdown.py` drives the real `main()`
with real signals: idle stop after one tick, stop mid-tick (that tick's committed
run is enqueued once, no further tick), stop during initialization (no tick),
repeated signals, handlers installed before initialization, and unchanged
normal ticking. Against the old entrypoint the idle and mid-tick cases block
for the full 30.0 s. CI runs `tests/drills/scheduler_shutdown_drill.sh` against
the built image in the `docker-build` job on every PR.

**Remaining limitations.** A tick in progress is never interrupted: with the
default batch limits a tick is short, but a tick blocked on an unreachable
database is bounded only by its connection and statement timeouts, and Docker
still SIGKILLs after 10 s in that case (safe; see the contract). A stop in the
first few hundred milliseconds of startup exits 143 rather than 0. The dev stack
(`docker-compose.yml`) gets the code fix but not `init: true`.
