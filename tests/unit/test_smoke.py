"""Smoke test: the package imports and exposes a version."""

import nlw


def test_package_version_present() -> None:
    assert isinstance(nlw.__version__, str)
    assert nlw.__version__
