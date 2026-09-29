"""B03: a deployed planner never falls back to the code-default model."""

import pytest
from pydantic import ValidationError

from nlw.core.config import Settings


def _settings(**kw: object) -> Settings:
    return Settings(_env_file=None, **kw)  # type: ignore[call-arg, arg-type]


@pytest.mark.parametrize("env", ["staging", "production"])
def test_deployed_anthropic_planner_requires_an_explicit_model(
    env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NLW_LLM_MODEL", raising=False)
    with pytest.raises(ValidationError, match="NLW_LLM_MODEL must be set explicitly"):
        _settings(app_env=env, NLW_LLM_PROVIDER="anthropic")


@pytest.mark.parametrize("env", ["staging", "production"])
def test_explicit_model_from_the_environment_is_accepted(
    env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NLW_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("NLW_LLM_MODEL", "claude-haiku-4-5-20251001")
    s = _settings(app_env=env)
    assert s.llm_model == "claude-haiku-4-5-20251001"


def test_local_and_stub_keep_the_development_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NLW_LLM_MODEL", raising=False)
    monkeypatch.delenv("NLW_LLM_PROVIDER", raising=False)
    assert _settings(app_env="local", NLW_LLM_PROVIDER="anthropic").llm_model
    assert _settings(app_env="production").llm_provider == "stub"  # stub never calls a model


def test_prod_compose_always_passes_the_deployed_model() -> None:
    """The deployed default lives in compose (the reviewed deployment file), so
    the new requirement is satisfied by every existing staging/production host."""
    from pathlib import Path

    text = (Path(__file__).resolve().parents[2] / "docker-compose.prod.yml").read_text()
    assert "NLW_LLM_MODEL: ${NLW_LLM_MODEL:-claude-haiku-4-5-20251001}" in text
