"""Anthropic implementation of :class:`LLMProvider` (M6 reference provider).

Uses the official async SDK and forces structured output via a single tool whose
input schema is the ``PlannerOutput`` JSON schema. The API key is PLATFORM
config (never a tenant/connector secret) and is never logged or echoed. Provider
faults are mapped to the planner's typed errors; the key never appears in them.

Imported lazily by ``build_llm_provider`` only when ``llm_provider='anthropic'``.
"""

from typing import Any

from nlw.planner.provider import (
    LLMAuthError,
    LLMInvalidOutputError,
    LLMRequest,
    LLMResult,
    LLMTimeoutError,
    LLMUnavailableError,
    clamp_max_output_tokens,
    clamp_timeout_s,
)

_PLAN_TOOL_NAME = "emit_workflow_plan"


class AnthropicProvider:
    """Async Anthropic provider producing a strict ``PlannerOutput`` via tool use."""

    def __init__(self, api_key: str | None, model: str) -> None:
        if not api_key:
            # Deterministic misconfiguration, surfaced as auth (never leaks a key).
            raise LLMAuthError("anthropic provider requires a platform LLM API key")
        # Import here so the SDK is only needed when this provider is selected.
        import anthropic

        # The SDK boundary is intentionally loosely typed: this is a thin adapter
        # that maps SDK calls/exceptions to our typed protocol. Keeping it `Any`
        # avoids coupling strict typing to the SDK's evolving TypedDict overloads.
        self._anthropic: Any = anthropic
        self._client: Any = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        tool: dict[str, Any] = {
            "name": _PLAN_TOOL_NAME,
            "description": "Return the proposed workflow plan as structured data.",
            "input_schema": req.output_schema,
        }
        try:
            message = await self._client.messages.create(
                model=self._model,
                max_tokens=clamp_max_output_tokens(req.max_output_tokens),
                system=req.system,
                messages=[{"role": "user", "content": req.user}],
                tools=[tool],
                tool_choice={"type": "tool", "name": _PLAN_TOOL_NAME},
                timeout=float(clamp_timeout_s(req.timeout_s)),
            )
        except self._anthropic.APITimeoutError:
            raise LLMTimeoutError("anthropic request timed out") from None
        except self._anthropic.AuthenticationError:
            raise LLMAuthError("anthropic rejected the platform API key") from None
        except (
            self._anthropic.APIConnectionError,
            self._anthropic.InternalServerError,
            self._anthropic.RateLimitError,
        ):
            raise LLMUnavailableError("anthropic is unavailable") from None
        except self._anthropic.APIStatusError:
            # Any other non-2xx: treat as unavailable rather than leaking detail.
            raise LLMUnavailableError("anthropic returned an error status") from None

        raw_json = _extract_tool_json(self._anthropic, message)
        usage = getattr(message, "usage", None)
        return LLMResult(
            raw_json=raw_json,
            model=getattr(message, "model", self._model),
            input_tokens=getattr(usage, "input_tokens", None),
            output_tokens=getattr(usage, "output_tokens", None),
            stop_reason=getattr(message, "stop_reason", None),
        )


def _extract_tool_json(anthropic_mod: Any, message: Any) -> str:
    """Pull the tool-use input (the plan) out of the message and JSON-encode it."""
    import json

    for block in getattr(message, "content", []) or []:
        if getattr(block, "type", None) == "tool_use" and getattr(block, "name", None) == (
            _PLAN_TOOL_NAME
        ):
            return json.dumps(block.input)
    raise LLMInvalidOutputError("anthropic did not return the expected plan tool call")
