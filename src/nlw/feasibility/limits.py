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


DEFAULT_LIMITS = PlatformLimits()
