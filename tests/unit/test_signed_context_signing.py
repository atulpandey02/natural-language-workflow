"""Unit tests for the signed DB context signer (M11.5 P3B): canonical encoding
(pinned golden vectors), fixed claim shapes per purpose, key/ttl validation,
key-file loading, and that key material never leaks through repr/str/errors."""

import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from nlw.tenancy.signing import (
    ALL_GUCS,
    MAX_TTL_S,
    ContextSigner,
    ContextSigningError,
    Purpose,
    SecretBytes,
    canonical_message,
    compute_mac,
    generate_test_key,
    load_key_file,
)

VECTORS = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "ctx_golden_vectors.json").read_text()
)
KEY = SecretBytes(bytes.fromhex(VECTORS["key_hex"]))


@pytest.mark.parametrize("v", VECTORS["vectors"], ids=[v["purpose"] for v in VECTORS["vectors"]])
def test_golden_vectors_message_and_mac(v: dict[str, Any]) -> None:
    fields = {
        k: v[k] for k in ("key_id", "db_role", "purpose", "user_id", "tenant_id", "run_id", "nonce")
    }
    msg = canonical_message(
        issued_at=int(v["issued_at"]), expires_at=int(v["expires_at"]), **fields
    )
    assert msg.decode() == v["message"]
    assert compute_mac(KEY, msg) == v["mac"]


def test_length_prefixing_is_unambiguous() -> None:
    # Moving a character across a field boundary MUST change the message even
    # though the concatenated characters are identical.
    a = canonical_message(
        key_id="ab",
        db_role="c",
        purpose="api_identity",
        user_id="",
        tenant_id="",
        run_id="",
        issued_at=1,
        expires_at=2,
        nonce="0" * 32,
    )
    b = canonical_message(
        key_id="a",
        db_role="bc",
        purpose="api_identity",
        user_id="",
        tenant_id="",
        run_id="",
        issued_at=1,
        expires_at=2,
        nonce="0" * 32,
    )
    assert a != b


def test_every_field_change_invalidates_the_mac() -> None:
    base = dict(
        key_id="k",
        db_role="nlw_app",
        purpose="api_request",
        user_id=str(uuid.uuid4()),
        tenant_id=str(uuid.uuid4()),
        run_id="",
        issued_at=1000,
        expires_at=1100,
        nonce="a" * 32,
    )
    ref = compute_mac(KEY, canonical_message(**base))  # type: ignore[arg-type]
    mutations = {
        "key_id": "k2",
        "db_role": "nlw_worker",
        "purpose": "api_identity",
        "user_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
        "issued_at": 1001,
        "expires_at": 1101,
        "nonce": "b" * 32,
    }
    for field, value in mutations.items():
        mutated = {**base, field: value}
        assert compute_mac(KEY, canonical_message(**mutated)) != ref, field  # type: ignore[arg-type]


def test_non_ascii_field_rejected() -> None:
    with pytest.raises(ContextSigningError):
        canonical_message(
            key_id="ké",
            db_role="nlw_app",
            purpose="api_identity",
            user_id="",
            tenant_id="",
            run_id="",
            issued_at=1,
            expires_at=2,
            nonce="0" * 32,
        )


def _signer(purpose: Purpose, **kw: object) -> ContextSigner:
    return ContextSigner(purpose=purpose, key_id="k-1", key=KEY, **kw)  # type: ignore[arg-type]


def test_purpose_shapes_are_enforced() -> None:
    u, t, r = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    ok = _signer(Purpose.API_IDENTITY).sign(user_id=u)
    assert (ok.user_id, ok.tenant_id, ok.run_id) == (u, None, None)
    with pytest.raises(ContextSigningError):
        _signer(Purpose.API_IDENTITY).sign(user_id=u, tenant_id=t)
    with pytest.raises(ContextSigningError):
        _signer(Purpose.API_REQUEST).sign(user_id=u)  # no tenant
    with pytest.raises(ContextSigningError):
        _signer(Purpose.API_REQUEST).sign(user_id=u, tenant_id=t, run_id=r)
    with pytest.raises(ContextSigningError):
        _signer(Purpose.WORKER_EXECUTION).sign(user_id=u, tenant_id=t)  # never a human
    with pytest.raises(ContextSigningError):
        _signer(Purpose.WORKER_EXECUTION).sign()  # needs tenant
    with pytest.raises(ContextSigningError):
        _signer(Purpose.SCHEDULER_RECONCILE).sign(tenant_id=t)
    assert _signer(Purpose.SCHEDULER_RECONCILE).sign().tenant_id is None


def test_db_role_is_fixed_by_purpose_not_caller() -> None:
    assert _signer(Purpose.WORKER_EXECUTION).db_role == "nlw_worker"
    with pytest.raises(ContextSigningError):
        ContextSigner(purpose=Purpose.WORKER_EXECUTION, key_id="k", key=KEY, db_role="nlw_app")


def test_ttl_and_key_id_bounds() -> None:
    with pytest.raises(ContextSigningError):
        _signer(Purpose.API_IDENTITY, ttl_s=0)
    with pytest.raises(ContextSigningError):
        _signer(Purpose.API_IDENTITY, ttl_s=MAX_TTL_S + 1)
    with pytest.raises(ContextSigningError):
        ContextSigner(purpose=Purpose.API_IDENTITY, key_id="bad id!", key=KEY)
    with pytest.raises(ContextSigningError):
        SecretBytes(b"short")


def test_signed_context_gucs_and_expiry() -> None:
    s = _signer(Purpose.API_REQUEST, ttl_s=30, clock=lambda: 1_700_000_000.9)
    ctx = s.sign(user_id=uuid.uuid4(), tenant_id=uuid.uuid4())
    gucs = ctx.as_gucs()
    assert set(gucs) == set(ALL_GUCS)
    assert gucs["app.ctx_iat"] == "1700000000" and gucs["app.ctx_exp"] == "1700000030"
    assert len(gucs["app.ctx_nonce"]) == 32 and len(gucs["app.ctx_mac"]) == 64
    # A second signing yields a fresh nonce/tag (no reuse across transactions).
    assert s.sign(user_id=ctx.user_id, tenant_id=ctx.tenant_id).nonce != ctx.nonce


def test_no_material_in_repr_or_str() -> None:
    s = _signer(Purpose.API_IDENTITY)
    ctx = s.sign(user_id=uuid.uuid4())
    for text in (repr(s), str(s), repr(KEY), str(KEY), repr(ctx)):
        assert VECTORS["key_hex"] not in text
        assert ctx.mac not in text
        assert ctx.nonce not in text


def test_load_key_file_permissions_and_format(tmp_path: Path) -> None:
    good = tmp_path / "k.key"
    good.write_text(generate_test_key() + "\n")
    good.chmod(0o600)
    assert len(load_key_file(good).reveal()) == 32
    loose = tmp_path / "loose.key"
    loose.write_text(generate_test_key())
    loose.chmod(0o644)
    with pytest.raises(ContextSigningError):
        load_key_file(loose)  # strict by default
    assert load_key_file(loose, strict_permissions=False)
    short = tmp_path / "short.key"
    short.write_text("abcd")
    short.chmod(0o600)
    with pytest.raises(ContextSigningError):
        load_key_file(short)
    with pytest.raises(ContextSigningError) as exc:
        load_key_file(tmp_path / "missing.key")
    assert "missing.key" in str(exc.value)  # message names the file, never contents


def test_apply_sql_is_a_constant_that_enumerates_every_guc_in_order() -> None:
    """``_APPLY_SQL`` is a literal statement (never string-built, so the platform
    SQL-injection guard holds); this pins its literal GUC names and bound-parameter
    positions to ``ALL_GUCS`` so the two cannot drift apart."""
    from nlw.tenancy.session import _APPLY_SQL, _params

    sql = _APPLY_SQL.text
    positions = [sql.index(f"set_config('{name}', :v{i}, true)") for i, name in enumerate(ALL_GUCS)]
    assert positions == sorted(positions)  # same order as ALL_GUCS
    assert sql.count("set_config(") == len(ALL_GUCS)
    ctx = ContextSigner(Purpose.API_IDENTITY, "k", SecretBytes(b"\x01" * 32)).sign(
        user_id=uuid.UUID(int=1)
    )
    params = _params(ctx)
    assert set(params) == {f"v{i}" for i in range(len(ALL_GUCS))}
    assert params["v0"] == "1" and params["v3"] == "api_identity"
