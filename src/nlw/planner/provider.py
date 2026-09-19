"""LLMProvider abstraction (M6, BYOK-ready).

The planner depends only on this protocol, never on a concrete SDK. Providers
are async so FastAPI is not forced to threadpool a blocking client. Failures are
split into infrastructure faults (timeout/unavailable/auth -> HTTP 5xx, never a
feasibility REJECT) and deterministic bad-output (-> PLANNER_INVALID_OUTPUT).

``temperature``/``top_p`` and similar knobs are intentionally NOT part of the
generic request; newer Claude models have moved away from them, and any
provider-specific control belongs inside a provider implementation.
"""

import json
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from nlw.core.config import Settings
from nlw.planner.schema import PlannerOutput

# Hard platform caps applied regardless of tenant/settings values.
_TIMEOUT_CAP_S = 60
_MAX_OUTPUT_TOKENS_CAP = 8192


class LLMProviderError(Exception):
    """Base for planner-provider failures (never carries the API key)."""


class LLMTimeoutError(LLMProviderError):
    """Provider timed out — infrastructure fault (retryable; HTTP 503)."""


class LLMUnavailableError(LLMProviderError):
    """Provider unreachable/5xx — infrastructure fault (retryable; HTTP 503)."""


class LLMAuthError(LLMProviderError):
    """Provider rejected the platform key — misconfiguration (HTTP 502)."""


class LLMInvalidOutputError(LLMProviderError):
    """Model output was not valid structured JSON — deterministic (REJECT)."""


@dataclass(frozen=True)
class LLMRequest:
    system: str
    user: str
    output_schema: dict[str, object]
    max_output_tokens: int
    timeout_s: int


@dataclass(frozen=True)
class LLMResult:
    raw_json: str = field(repr=False)  # parsed by the planner; not persisted/logged
    model: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    stop_reason: str | None = None


@runtime_checkable
class LLMProvider(Protocol):
    async def generate_plan(self, req: LLMRequest) -> LLMResult: ...


class StubLLMProvider:
    """Deterministic, keyless provider for local/dev and CI.

    Emits a valid, empty-plan ``PlannerOutput`` that asks for clarification, so
    the full pipeline runs without a network call or an API key. It never
    fabricates tools or connectors.
    """

    model = "stub"

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        output = PlannerOutput(
            workflow_name="stub proposal",
            clarification_needed=True,
            clarification_questions=[
                "The stub planner cannot infer intent; connect a real LLM provider."
            ],
            steps=[],
        )
        return LLMResult(
            raw_json=output.model_dump_json(),
            model=self.model,
            stop_reason="stub",
        )


def clamp_timeout_s(value: int) -> int:
    return max(1, min(value, _TIMEOUT_CAP_S))


def clamp_max_output_tokens(value: int) -> int:
    return max(1, min(value, _MAX_OUTPUT_TOKENS_CAP))


def build_llm_provider(settings: Settings) -> LLMProvider:
    """Select the provider by config. ``anthropic`` is imported lazily so the
    default stub path needs neither the SDK nor a key."""
    if settings.llm_provider == "stub":
        return StubLLMProvider()
    if settings.llm_provider == "anthropic":
        from nlw.planner.anthropic_provider import AnthropicProvider

        return AnthropicProvider(
            api_key=settings.llm_api_key,
            model=settings.llm_model,
        )
    # Unreachable: llm_provider is a constrained Literal.
    raise LLMProviderError(f"unknown llm provider: {settings.llm_provider}")


def parse_planner_output(raw_json: str) -> PlannerOutput:
    """Strictly parse model output into ``PlannerOutput``.

    Raises :class:`LLMInvalidOutputError` on any structural/schema violation.
    """
    try:
        return PlannerOutput.model_validate_json(raw_json)
    except (ValueError, json.JSONDecodeError) as exc:
        raise LLMInvalidOutputError("planner output failed schema validation") from exc
