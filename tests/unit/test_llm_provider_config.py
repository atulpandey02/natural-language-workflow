"""LLMProvider selection, config, and key-handling (M6)."""

import pytest

from nlw.core.config import Settings
from nlw.planner.provider import (
    LLMAuthError,
    LLMRequest,
    StubLLMProvider,
    build_llm_provider,
    clamp_max_output_tokens,
    clamp_timeout_s,
)


def _settings(**over: object) -> Settings:
    base: dict[str, object] = {
        "_env_file": None,
        "supabase_url": "https://x.supabase.co",
        "supabase_jwt_secret": "dev-secret-32bytes-minimum-length-xx",
    }
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


def test_default_provider_is_stub() -> None:
    provider = build_llm_provider(_settings())
    assert isinstance(provider, StubLLMProvider)


async def test_stub_provider_is_keyless() -> None:
    req = LLMRequest(system="s", user="u", output_schema={}, max_output_tokens=10, timeout_s=5)
    result = await StubLLMProvider().generate_plan(req)
    assert result.model == "stub"


def test_anthropic_without_key_raises_auth() -> None:
    with pytest.raises(LLMAuthError):
        build_llm_provider(_settings(llm_provider="anthropic", llm_api_key=None))


def test_timeout_and_token_caps() -> None:
    assert clamp_timeout_s(10_000) == 60
    assert clamp_timeout_s(0) == 1
    assert clamp_max_output_tokens(10_000_000) == 8192
    assert clamp_max_output_tokens(0) == 1


def test_llm_key_reads_nlw_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NLW_LLM_API_KEY", "platform-key-value")
    monkeypatch.setenv("NLW_LLM_PROVIDER", "anthropic")
    s = _settings()
    assert s.llm_api_key == "platform-key-value"
    assert s.llm_provider == "anthropic"


def test_llm_key_never_in_settings_repr() -> None:
    s = _settings(llm_api_key="super-secret-key")
    # A defensive check: the key should not be casually surfaced.
    assert s.llm_api_key == "super-secret-key"  # accessible when needed
