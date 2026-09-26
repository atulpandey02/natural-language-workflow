# ADR-005 — LLMProvider abstraction & BYOK

- Status: Accepted
- Date: 2026-09-19

## Context

The planner (ADR-004) needs an LLM, but the platform must not couple to one SDK,
must keep the model's key out of tenant/connector secret handling, and must be
fully testable in CI without a live key or network. It must also be honest about
what it can and cannot guarantee regarding data in model context.

## Decision

- **Protocol, not SDK.** The planner depends only on
  `LLMProvider.generate_plan(req) -> LLMResult`, which is **async** so FastAPI is
  not forced to threadpool a blocking client. `LLMRequest` carries `system`,
  `user`, the `PlannerOutput` JSON schema, `max_output_tokens`, and `timeout_s`.
  It deliberately omits `temperature`/`top_p`/`top_k`: newer Claude models have
  moved away from them, and any provider-specific control lives inside a provider
  implementation.
- **Reference provider:** `AnthropicProvider` (official async SDK), forcing
  structured output via a single tool whose input schema is `PlannerOutput`.
  Default model `claude-sonnet-5` (configurable).
- **Keyless default + CI:** `StubLLMProvider` runs without a key or network (it
  requests clarification), and tests inject scripted/spy async providers. **No CI
  test requires a live Anthropic key.**
- **Bounds:** `timeout_s` and `max_output_tokens` are hard-capped in the provider
  layer; the API rejects prompts over `llm_max_prompt_chars` (422) before any
  call.
- **Failure classification (mirrors M5 retryable-vs-deterministic):** provider
  timeout/unavailable → HTTP 503; provider auth/misconfiguration → HTTP 502;
  **no** feasibility REJECT row is fabricated for an infrastructure fault. Invalid
  structured output after the bounded retry → deterministic
  `PLANNER_INVALID_OUTPUT` → a REJECT proposal (safe: never executable).
- **Key placement / process isolation.** The platform LLM key
  (`NLW_LLM_API_KEY`) is **platform configuration, not a tenant/connector
  secret**. Because M6 planning runs in the API, the key is injected into the
  **API process only** — never in the shared Compose env block, and never in the
  worker or scheduler. It is never logged and never placed in model context. A
  configuration test asserts the key is present for `api` and absent for
  `worker`/`scheduler`.
- **BYOK (interface now, tenant keys later).** Provider construction is driven by
  config today (platform key). Tenant-supplied keys are a future *key source*
  that resolves via the `SecretStore` **worker-side**, so the API never holds
  tenant secrets; that path is deferred with planning that runs worker-side.

## Security guarantee (stated precisely)

The platform guarantees that it does **not** inject platform-managed connector
secrets, `secret_ref` values, DB passwords, OAuth tokens, internal DB
credentials, or the LLM API key into model context. It **cannot** guarantee that
a user did not type sensitive information into their own prompt; user-authored
prompt content is outside the stored-secret non-exposure guarantee and may be
copied by the model into plan args or clarification questions. Observability
records only metadata (`prompt_len`, provider, model, latency, token usage,
parse/retry status) — never the raw prompt (not even at DEBUG) and never the raw
provider response.

## Alternatives considered

- **Call the HTTP API via `httpx` directly** — viable, but the official SDK gives
  typed errors and structured tool output for little cost; kept behind the
  protocol so it can be swapped.
- **A synchronous provider interface** — rejected: forces threadpooling in the
  async API; async keeps the request path clean.
- **Persisting a keyed/HMAC prompt fingerprint for observability** — deferred:
  M6 stores only `prompt_len` and correlates by `proposal_id`; if stable
  fingerprinting is needed later it will use an explicit keyed digest, not a
  plain hash. *(Historical note: since M12B-A, migration `0017`, `plan_proposals`
  also persists the bounded, tenant-scoped request text with a plain SHA-256
  integrity digest for provenance — see ADR-026. Logs still carry only
  `prompt_len`.)*

## Consequences

- The planner is provider-agnostic and CI-safe; a real provider plugs in via
  config without touching the planner.
- The model key is structurally isolated to the API process and out of model
  context, and the platform's data guarantee is stated honestly.
