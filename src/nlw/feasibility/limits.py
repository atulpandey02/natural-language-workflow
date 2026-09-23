"""Platform limits for deterministic feasibility (M6).

Hard bounds the LLM can never widen. Kept tiny and explicit; the engine treats
these as authoritative regardless of any value a plan or tenant proposes.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformLimits:
    max_steps: int = 50
    max_depends_on_per_step: int = 20
    max_step_timeout_seconds: int = 300
    max_total_timeout_seconds: int = 1800
    # Serialized-size bounds (M12B-A). A plan is persisted verbatim into
    # ``workflow_versions.plan`` and its step args into ``step_runs.input``; the
    # step-count/DAG bounds above do not cap the BYTES a single arg blob can carry
    # (generic ``extra='allow'`` tool args, a giant literal, a huge JSON body).
    # These caps fail such plans closed with a stable code instead of writing an
    # unbounded blob to durable state. Security-critical schemas are never
    # truncated — an over-cap plan is rejected, never silently trimmed.
    max_step_args_bytes: int = 16_384  # per-step args, JSON-serialized
    max_plan_bytes: int = 262_144  # whole plan (steps), JSON-serialized


DEFAULT_LIMITS = PlatformLimits()
