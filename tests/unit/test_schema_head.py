"""Expected-migration-head resolution is cached (M9, readiness schema check)."""

from nlw.db.schema import expected_head


def test_expected_head_nonempty_and_cached() -> None:
    head = expected_head()
    assert isinstance(head, str) and head
    # lru_cache: repeated calls return the identical cached object (no rebuild).
    assert expected_head() is head
