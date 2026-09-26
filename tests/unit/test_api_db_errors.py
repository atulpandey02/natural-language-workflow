"""Pure classification of database failures (no DB): SQLSTATE + constraint name."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import DBAPIError, IntegrityError, InterfaceError, OperationalError

from nlw.api import db_errors


class _Orig(Exception):
    def __init__(self, sqlstate: str | None, constraint: str | None = None) -> None:
        super().__init__("driver text password=hunter2")
        self.sqlstate = sqlstate
        self.diag = SimpleNamespace(constraint_name=constraint)


def _err(sqlstate: str | None, constraint: str | None = None, cls: type = DBAPIError) -> DBAPIError:
    return cls("SQL", {}, _Orig(sqlstate, constraint))  # type: ignore[no-any-return]


def test_sqlstate_and_constraint_extraction() -> None:
    e = _err("23505", "uq_invitation_pending_email", IntegrityError)
    assert db_errors.sqlstate(e) == "23505"
    assert db_errors.constraint_name(e) == "uq_invitation_pending_email"
    assert db_errors.sqlstate(RuntimeError("x")) is None
    assert db_errors.constraint_name(RuntimeError("x")) is None
    bare = DBAPIError("SQL", {}, Exception("no attrs"))
    assert db_errors.sqlstate(bare) is None and db_errors.constraint_name(bare) is None


def test_only_the_exact_pending_invitation_index_is_a_duplicate() -> None:
    idx = db_errors.PENDING_INVITATION_UNIQUE_INDEX
    assert db_errors.is_unique_violation_of(_err("23505", idx, IntegrityError), idx)
    # Different index, different SQLSTATE, or no constraint reported -> never.
    assert not db_errors.is_unique_violation_of(_err("23505", "uq_invitation_token_hash"), idx)
    assert not db_errors.is_unique_violation_of(_err("23503", idx), idx)
    assert not db_errors.is_unique_violation_of(_err("23505", None), idx)
    assert not db_errors.is_unique_violation_of(_err(None, None, OperationalError), idx)


@pytest.mark.parametrize(
    "exc, expected",
    [
        (_err("08006"), True),  # connection failure
        (_err("08001"), True),
        (_err("53300"), True),  # too many connections
        (_err("57P01"), True),  # admin shutdown
        (_err("57014"), True),  # statement timeout / query cancelled
        (_err("40001"), True),  # serialization failure
        (_err("40P01"), True),  # deadlock
        (_err(None, None, OperationalError), True),  # driver connect failure, no state
        (_err(None, None, InterfaceError), True),
        (_err("42501"), False),  # permission denied: NOT transient
        (_err("23505", "x"), False),
        (_err("22023"), False),
        (_err("XX000"), False),  # internal error: unexpected, not "retry later"
        (_err("P0001"), False),
        (_err(None), False),  # generic DBAPIError with no state: unexpected
    ],
)
def test_is_unavailable_table(exc: DBAPIError, expected: bool) -> None:
    assert db_errors.is_unavailable(exc) is expected


def test_invalidated_connection_is_unavailable() -> None:
    e = _err(None)
    e.connection_invalidated = True
    assert db_errors.is_unavailable(e)


def test_unavailable_response_is_sanitized_with_retry_after() -> None:
    http = db_errors.unavailable(_err("08006"), "invitation.create")
    assert isinstance(http, HTTPException)
    assert http.status_code == 503
    assert http.detail == "service temporarily unavailable"
    assert http.headers == {"Retry-After": "5"}
    assert "hunter2" not in str(http.detail)
