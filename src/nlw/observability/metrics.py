"""Prometheus metrics (M9, ADR-016).

Curated, low-cardinality instrumentation for the three process roles. Metric
LABELS never carry high-cardinality identifiers (tenant_id, run_id, step_id,
connector_id) — those belong in structured logs and the database. Labels are
restricted to bounded dimensions: HTTP method/route, tool name, outcome class,
error class, and the process role.

Each process serves ``/metrics`` on its own INTERNAL port via
``start_metrics_server``; the port is never published publicly (see
docker-compose). Callers record through the typed helper functions below and
never touch the prometheus objects directly, which keeps the strict-typed engine
and scheduler modules clean.
"""

import contextlib
import threading
from collections.abc import Callable, Iterable

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    start_http_server,
)
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector

from nlw.core.config import Settings

# --- HTTP (API) ---
_HTTP_REQUESTS = Counter(
    "nlw_http_requests_total",
    "HTTP requests handled by the API.",
    labelnames=("method", "route", "status"),
)
_HTTP_LATENCY = Histogram(
    "nlw_http_request_duration_seconds",
    "HTTP request latency (seconds).",
    labelnames=("method", "route"),
)

# --- Planner / feasibility (API) ---
_PLANS = Counter(
    "nlw_plans_total",
    "Plan proposals by final feasibility status.",
    labelnames=("status",),
)
_PLANNER_LATENCY = Histogram(
    "nlw_planner_latency_seconds",
    "Planner (LLM + feasibility) latency (seconds).",
)
# --- AI-core behavior (M12B-A, Part I). All labels are bounded vocabularies:
# never tenant/run/step ids, prompt text, or tool output. ---
# Structurally invalid model output (unparseable / schema violation) -> a
# deterministic PLANNER_INVALID_OUTPUT reject. A rising rate signals a model /
# provider / schema-drift problem distinct from ordinary business rejects.
_PLANNER_INVALID = Counter(
    "nlw_planner_invalid_output_total",
    "Planner responses rejected as structurally invalid (schema/parse failure).",
)
# Feasibility REJECT reasons by stable code (FeasibilityCode is a small fixed
# vocabulary). One increment per reject finding.
_FEASIBILITY_REJECT = Counter(
    "nlw_feasibility_reject_total",
    "Feasibility reject findings by stable code.",
    labelnames=("code",),
)
# Proposed plan shape (accepted plans that reached feasibility).
_PLAN_STEPS = Histogram(
    "nlw_plan_steps",
    "Number of steps in a proposed plan.",
    buckets=(0, 1, 2, 3, 5, 10, 20, 50, 100),
)
_PLAN_BYTES = Histogram(
    "nlw_plan_bytes",
    "Serialized size of a proposed plan (bytes).",
    buckets=(256, 1024, 4096, 16384, 65536, 262144),
)
# Planner token usage (direction is bounded: input|output). Cost/latency signal.
_PLANNER_TOKENS = Histogram(
    "nlw_planner_tokens",
    "Planner token usage per request.",
    labelnames=("direction",),
    buckets=(64, 256, 1024, 2048, 4096, 8192),
)
# Deterministic grounded run summary outcomes (RunOutcome is a fixed vocabulary).
_RUN_SUMMARY = Counter(
    "nlw_run_summary_total",
    "Grounded run summaries produced, by run outcome.",
    labelnames=("outcome",),
)
# Stale-plan re-validation blocks (M12B-A addendum, Part 2). Both labels are fixed
# vocabularies: outcome (STALE_PLAN/POLICY_DENIED/INVALID_PLAN) and reason (a
# stable FeasibilityCode value). Never customer data.
_STALE_PLAN = Counter(
    "nlw_stale_plan_total",
    "Re-validation blocks of a previously-accepted plan, by outcome and reason.",
    labelnames=("outcome", "reason"),
)
# Queue-to-start latency: run creation -> first RUNNING transition (how long a run
# waited before a worker picked it up). Observed once, at the actual start.
_QUEUE_TO_START = Histogram(
    "nlw_run_queue_to_start_seconds",
    "Seconds from run creation to its first RUNNING transition.",
)
# Approval wait: request -> decision. Observed once, when a decision is recorded.
_APPROVAL_WAIT = Histogram(
    "nlw_approval_wait_seconds",
    "Seconds a run waited for an approval decision.",
    buckets=(1, 10, 60, 300, 1800, 7200, 86400),
)

# --- Tools / actions (worker) ---
_TOOL_LATENCY = Histogram(
    "nlw_tool_latency_seconds",
    "Tool execution latency (seconds).",
    labelnames=("tool", "outcome"),
)
_ACTION_ATTEMPTS = Counter(
    "nlw_action_attempts_total",
    "External action attempts by outcome.",
    labelnames=("tool", "outcome"),
)

# --- Engine advancement (worker) ---
_ADVANCE = Counter(
    "nlw_advance_total",
    "Run advancements by result.",
    labelnames=("result",),
)
_ADVANCE_LATENCY = Histogram(
    "nlw_advance_latency_seconds",
    "Run advancement latency (seconds).",
)

# --- Scheduler ---
_SCHED_CREATED = Counter(
    "nlw_scheduler_runs_created_total",
    "Runs created by the due-schedule scanner.",
)
_SCHED_REENQUEUED = Counter(
    "nlw_scheduler_reconcile_reenqueued_total",
    "Stuck runs re-enqueued by the reconciler.",
)
_SCHED_BEYOND_HORIZON = Gauge(
    "nlw_scheduler_runs_beyond_horizon",
    "Recoverable runs currently past the recovery horizon (need operator action).",
)
# P1D: candidates the reconciler selected (post fairness + horizon + batch limit).
_SCHED_RECON_CANDIDATES = Counter(
    "nlw_scheduler_reconcile_candidates_total",
    "Eligible stuck runs selected by the reconciler (after fairness/horizon/limit).",
)
# P1D: eligible rows dropped by the per-tenant fairness cap this scan (they remain
# for a later scan). A persistently high value signals a noisy tenant.
_SCHED_RECON_FAIRNESS_DEFERRED = Counter(
    "nlw_scheduler_reconcile_fairness_deferred_total",
    "Eligible runs deferred by the per-tenant reconciliation fairness cap.",
)
# P1D: a due occurrence that already had its run (idempotent no-op insert), e.g. a
# second scheduler instance or a restart re-scanning the same occurrence.
_SCHED_OCCURRENCE_EXISTS = Counter(
    "nlw_scheduler_occurrence_exists_total",
    "Due occurrences whose run already existed (idempotent scheduler no-op).",
)

# --- Errors / rate limiting ---
_ERRORS = Counter(
    "nlw_errors_total",
    "Errors by class.",
    labelnames=("error_class",),
)
_RATE_LIMIT_REJECTED = Counter(
    "nlw_rate_limit_rejected_total",
    "Requests rejected by the rate limiter.",
    labelnames=("endpoint",),
)

# --- Capacity metrics (M11, D2) ---
# DB connection-pool checkout wait (time to acquire a pooled connection). Under
# pool saturation this rises; ~0 when there is headroom.
_DB_CHECKOUT_WAIT = Histogram(
    "nlw_db_pool_checkout_wait_seconds",
    "Time spent acquiring a pooled DB connection (seconds).",
)
# Total wall-clock time of a run, observed ONCE at the actual terminal transition
# (never on a replay that merely observes an already-terminal run).
_RUN_COMPLETION = Histogram(
    "nlw_run_completion_seconds",
    "Run wall-clock time from creation to terminal state (seconds).",
    labelnames=("result",),
)
# Scheduler lag: how far behind the earliest overdue occurrence the scheduler is.
_SCHEDULER_LAG = Gauge(
    "nlw_scheduler_lag_seconds",
    "Seconds by which the scheduler is behind the earliest overdue occurrence.",
)

# --- Signed database context (M11.5 P3B, ADR-024) ---
# Application-side only: PostgreSQL's verifier (app_ctx_claims) stays side-effect
# free and returns claims-or-NULL, never a reason. What the application CAN
# observe is its own self-check — "the key this process holds verifies against
# the database" — which is exactly the deployment / key-mismatch / rotation
# signal operators need. Labels are bounded: purpose (4 values), result
# (valid|invalid) and a fixed reason vocabulary. NEVER user, workspace, run,
# nonce, tag or key id.
_CTX_VERIFICATION = Counter(
    "nlw_ctx_verification_total",
    "Signed-context self-check verifications by purpose and result.",
    labelnames=("purpose", "result", "reason"),
)
_CTX_SIGNER_CONFIGURED = Gauge(
    "nlw_ctx_signer_configured",
    "1 when this process holds a usable signing key for the purpose, else 0.",
    labelnames=("purpose",),
)
_CTX_REASONS = frozenset({"none", "not_verified", "db_error", "signer_unavailable"})


# Scrape-time providers for pool/queue gauges. These read live values at collect()
# time so the numbers are current on every scrape. Providers are registered by the
# owning process (worker/api) and default to None (metric absent) otherwise.
_pool_provider: Callable[[], tuple[int, int]] | None = None  # (checked_out, overflow)
_queue_provider: Callable[[], int] | None = None  # ready messages in Redis transport


def register_pool_provider(fn: Callable[[], tuple[int, int]]) -> None:
    global _pool_provider
    _pool_provider = fn


def register_queue_provider(fn: Callable[[], int]) -> None:
    global _queue_provider
    _queue_provider = fn


class _CapacityCollector(Collector):
    """Yields current DB-pool and Redis queue-depth gauges at scrape time."""

    def collect(self) -> Iterable[GaugeMetricFamily]:
        checked_out = GaugeMetricFamily(
            "nlw_db_pool_checked_out", "DB connections currently checked out of the pool."
        )
        overflow = GaugeMetricFamily(
            "nlw_db_pool_overflow", "DB pool overflow connections currently in use."
        )
        if _pool_provider is not None:
            with contextlib.suppress(Exception):  # a metrics scrape must never raise
                co, ov = _pool_provider()
                checked_out.add_metric([], co)
                overflow.add_metric([], ov)
        yield checked_out
        yield overflow

        # queue_ready_depth = runnable messages currently waiting in the Redis
        # transport. NOT authoritative outstanding workflow state (durable state
        # lives in Postgres); a best-effort transport gauge only.
        queue = GaugeMetricFamily(
            "nlw_queue_ready_depth", "Runnable messages waiting in the Redis transport."
        )
        if _queue_provider is not None:
            with contextlib.suppress(Exception):
                queue.add_metric([], _queue_provider())
        yield queue


_capacity_registered = False


def register_capacity_collector() -> None:
    """Register the scrape-time capacity collector once."""
    global _capacity_registered
    if _capacity_registered:
        return
    REGISTRY.register(_CapacityCollector())
    _capacity_registered = True


_server_started = False
_server_lock = threading.Lock()


def start_metrics_server(settings: Settings, role: str) -> bool:
    """Start the internal Prometheus HTTP server for this process (idempotent).

    Returns True if a server is now running, False if metrics are disabled.
    The bound port is internal to the container and never published publicly.
    """
    global _server_started
    if not settings.metrics_enabled:
        return False
    with _server_lock:
        if _server_started:
            return True
        start_http_server(settings.metrics_port, addr=settings.metrics_host)
        _server_started = True
    return True


def render() -> tuple[bytes, str]:
    """Render the current metrics exposition (payload, content_type)."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


# --- Typed recording helpers (callers never touch prometheus objects) ---


def record_http(method: str, route: str, status_code: int, seconds: float) -> None:
    _HTTP_REQUESTS.labels(method=method, route=route, status=str(status_code)).inc()
    _HTTP_LATENCY.labels(method=method, route=route).observe(seconds)


def record_plan(status: str) -> None:
    _PLANS.labels(status=status).inc()


def observe_planner(seconds: float) -> None:
    _PLANNER_LATENCY.observe(seconds)


def record_planner_invalid_output() -> None:
    _PLANNER_INVALID.inc()


def record_feasibility_reject(code: str) -> None:
    """One reject finding by stable FeasibilityCode value (bounded vocabulary)."""
    _FEASIBILITY_REJECT.labels(code=code).inc()


def observe_plan_shape(steps: int, plan_bytes: int) -> None:
    _PLAN_STEPS.observe(steps)
    _PLAN_BYTES.observe(plan_bytes)


def observe_planner_tokens(input_tokens: int | None, output_tokens: int | None) -> None:
    if input_tokens is not None:
        _PLANNER_TOKENS.labels(direction="input").observe(input_tokens)
    if output_tokens is not None:
        _PLANNER_TOKENS.labels(direction="output").observe(output_tokens)


def record_run_summary(outcome: str) -> None:
    _RUN_SUMMARY.labels(outcome=outcome).inc()


def record_stale_plan(outcome: str, reason: str) -> None:
    """One re-validation block. ``reason`` is a stable FeasibilityCode value."""
    _STALE_PLAN.labels(outcome=outcome, reason=reason).inc()


def observe_queue_to_start(seconds: float) -> None:
    """Observe run creation -> first RUNNING (once, at the actual start)."""
    _QUEUE_TO_START.observe(max(0.0, seconds))


def observe_approval_wait(seconds: float) -> None:
    """Observe request -> decision (once, when a decision is recorded)."""
    _APPROVAL_WAIT.observe(max(0.0, seconds))


def observe_tool(tool: str, outcome: str, seconds: float) -> None:
    _TOOL_LATENCY.labels(tool=tool, outcome=outcome).observe(seconds)


def record_action_attempt(tool: str, outcome: str) -> None:
    _ACTION_ATTEMPTS.labels(tool=tool, outcome=outcome).inc()


def record_advance(result: str, seconds: float) -> None:
    _ADVANCE.labels(result=result).inc()
    _ADVANCE_LATENCY.observe(seconds)


def record_error(error_class: str) -> None:
    _ERRORS.labels(error_class=error_class).inc()


def record_scheduler_created(n: int) -> None:
    if n:
        _SCHED_CREATED.inc(n)


def record_reconcile(n: int) -> None:
    if n:
        _SCHED_REENQUEUED.inc(n)


def set_runs_beyond_horizon(n: int) -> None:
    _SCHED_BEYOND_HORIZON.set(n)


def record_reconcile_candidates(n: int) -> None:
    if n:
        _SCHED_RECON_CANDIDATES.inc(n)


def record_reconcile_fairness_deferred(n: int) -> None:
    if n:
        _SCHED_RECON_FAIRNESS_DEFERRED.inc(n)


def record_scheduler_occurrence_exists(n: int) -> None:
    if n:
        _SCHED_OCCURRENCE_EXISTS.inc(n)


def record_rate_limit_rejected(endpoint: str) -> None:
    _RATE_LIMIT_REJECTED.labels(endpoint=endpoint).inc()


def observe_db_checkout_wait(seconds: float) -> None:
    _DB_CHECKOUT_WAIT.observe(seconds)


def observe_run_completion(result: str, seconds: float) -> None:
    """Observe total run time at the ACTUAL terminal transition only (M11 D2)."""
    _RUN_COMPLETION.labels(result=result).observe(seconds)


def set_scheduler_lag(seconds: float) -> None:
    _SCHEDULER_LAG.set(seconds)


def record_ctx_verification(purpose: str, ok: bool, reason: str = "none") -> None:
    """Record one signed-context self-check (P3B). ``reason`` is coerced into the
    fixed vocabulary so a caller can never introduce an unbounded label value."""
    if reason not in _CTX_REASONS:
        reason = "not_verified"
    _CTX_VERIFICATION.labels(
        purpose=purpose, result="valid" if ok else "invalid", reason="none" if ok else reason
    ).inc()


def set_ctx_signer_configured(purpose: str, configured: bool) -> None:
    _CTX_SIGNER_CONFIGURED.labels(purpose=purpose).set(1 if configured else 0)
