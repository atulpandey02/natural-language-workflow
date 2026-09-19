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

import threading

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    start_http_server,
)

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


def record_rate_limit_rejected(endpoint: str) -> None:
    _RATE_LIMIT_REJECTED.labels(endpoint=endpoint).inc()
