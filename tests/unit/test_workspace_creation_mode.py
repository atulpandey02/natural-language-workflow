"""B01: the workspace-creation mode is operator configuration that fails closed."""

import pytest
from pydantic import ValidationError

from nlw.core.config import Settings


def _settings(**kw: object) -> Settings:
    return Settings(_env_file=None, **kw)  # type: ignore[call-arg, arg-type]


def test_default_mode_is_grant_everywhere() -> None:
    for env in ("local", "dev", "staging", "production"):
        assert _settings(app_env=env).workspace_creation_mode == "grant"


@pytest.mark.parametrize("env", ["local", "dev", "staging", "production"])
@pytest.mark.parametrize("mode", ["open", "OPEN", "", "any"])
def test_open_or_unknown_mode_refuses_to_start(env: str, mode: str) -> None:
    # The database has no ungated bootstrap, so there is no mode that skips it.
    with pytest.raises(ValidationError):
        _settings(app_env=env, workspace_creation_mode=mode)


def test_mode_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WORKSPACE_CREATION_MODE", "closed")
    assert _settings().workspace_creation_mode == "closed"
    monkeypatch.setenv("WORKSPACE_CREATION_MODE", "open")
    with pytest.raises(ValidationError):
        _settings()
