"""The customer-facing deletion statement (draft for owner approval) states
exactly the implemented retention contract and makes no claim it cannot keep."""

from __future__ import annotations

import re
from pathlib import Path

from nlw.core import retention as r

DOC = Path(__file__).resolve().parents[2] / "docs/security/offboarding-and-deletion.md"


def _statement() -> str:
    text = DOC.read_text()
    m = re.search(r"<!-- customer-statement -->\n(.*?)<!-- /customer-statement -->", text, re.S)
    assert m is not None, "the statement block is missing"
    return " ".join(line.lstrip("> ").strip() for line in m.group(1).splitlines())


def test_the_statement_states_the_approved_periods_from_the_contract() -> None:
    s = _statement()
    assert "access to it is disabled immediately" in s
    assert f"with a target of {r.DELETED_PURGE_DAYS} days" in s
    assert r.NONCURRENT_RETENTION_DAYS == r.OBJECT_BACKUP_RETENTION_DAYS == 30
    assert f"expire within {r.OBJECT_BACKUP_RETENTION_DAYS} days" in s
    assert r.DB_BACKUP_MONTHLY == 12 and "expire within twelve months" in s
    assert r.RECEIPT_RETENTION_DAYS == r.AUDIT_RETENTION_DAYS == 365
    assert f"for {r.RECEIPT_RETENTION_DAYS} days as audit evidence" in s
    # Every number in the statement is one of the contract's.
    numbers = {int(n) for n in re.findall(r"\b(\d+)\b", s)}
    assert numbers == {
        r.DELETED_PURGE_DAYS,
        r.OBJECT_BACKUP_RETENTION_DAYS,
        r.RECEIPT_RETENTION_DAYS,
    }


def test_the_statement_never_promises_what_is_not_implemented() -> None:
    s = _statement().lower()
    for claim in ("immediately deleted", "deleted immediately", "permanently deleted at once",
                  "erased immediately", "ready for customer", "customer data is supported",
                  "within 24 hours", "six months", "never stored"):  # fmt: skip
        assert claim not in s, claim
    # The grant-ledger scrub is described as what it is: workspace records only.
    assert "removed from our workspace records" in s
    assert "sign-in account is separate from the workspace and is not deleted" in s
    doc = DOC.read_text()
    assert "DRAFT FOR OWNER APPROVAL" in doc and "not published, not in effect" in doc
    assert "COMPLIANCE retention" in doc
