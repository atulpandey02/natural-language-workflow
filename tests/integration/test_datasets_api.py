"""Dataset metadata API (ADR-029) through the real app, auth and PostgreSQL.

Flag OFF (the default, and the only value staging/production accept): no dataset
route exists. Flag ON (local/test only): admins manage metadata containers,
members read, another workspace's ids are indistinguishable from nonexistent
ones, hostile input gets stable 422 codes, deletion is an idempotent 202, and
nothing returned carries a storage location. The pilot ``/analytics/datasets``
catalog is untouched.
"""

import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from nlw.api.app import create_app

pytestmark = pytest.mark.integration

_SECRET = "dev-secret-for-tests-32bytes-min-length"


def _hdr(user_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, str]:
    token = jwt.encode(
        {
            "iss": "https://proj.supabase.co/auth/v1",
            "aud": "authenticated",
            "exp": int(time.time()) + 300,
            "sub": f"sub-{user_id}",
            "email": f"{user_id}@example.com",
        },
        _SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}", "X-Workspace-Id": str(tenant_id)}


@pytest.fixture
def on(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    settings = pg_stack.settings.model_copy(update={"datasets_api_enabled": True})
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def off(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


def _seed_version(pg: SimpleNamespace, tenant_id: uuid.UUID, dataset_id: str) -> str:
    """Versions have no public create route; seed one as the owner role."""
    vid = uuid.uuid4()
    with psycopg.connect(pg.owner_libpq, autocommit=True) as c:
        uid = c.execute(
            "SELECT user_id FROM memberships WHERE workspace_id = %s LIMIT 1", (tenant_id,)
        ).fetchone()
        assert uid is not None
        n = c.execute(
            "UPDATE datasets SET last_version_number = last_version_number + 1 "
            "WHERE id = %s RETURNING last_version_number",
            (dataset_id,),
        ).fetchone()
        assert n is not None
        c.execute(
            "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
            "original_filename, media_type, declared_size_bytes, created_by) "
            "VALUES (%s,%s,%s,%s,'QUARANTINED','sales.csv','text/csv',1234,%s)",
            (vid, tenant_id, dataset_id, n[0], uid[0]),
        )
    return str(vid)


def test_flag_off_mounts_no_dataset_route(off: TestClient, pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member("owner")
    h = _hdr(m.user_id, m.tenant_id)
    assert off.get("/datasets", headers=h).status_code == 404
    assert off.post("/datasets", headers=h, json={"name": "x"}).status_code in (404, 405)
    assert off.get(f"/datasets/{uuid.uuid4()}", headers=h).status_code == 404
    app = off.app
    assert isinstance(app, FastAPI)
    assert not [r for r in app.routes if getattr(r, "path", "").startswith("/datasets")]
    # The pilot catalog is a different, unchanged surface.
    assert off.get("/analytics/datasets", headers=h).status_code == 200


def test_admin_lifecycle_and_member_read_only(on: TestClient, pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member("owner")
    owner = _hdr(m.user_id, m.tenant_id)
    admin = _hdr(pg_stack.add_membership(m.tenant_id, "admin"), m.tenant_id)
    member = _hdr(pg_stack.add_membership(m.tenant_id, "member"), m.tenant_id)

    r = on.post("/datasets", headers=admin, json={"name": "  Sales  2026 ", "description": "Q"})
    assert r.status_code == 201, r.text
    d = r.json()
    assert (d["name"], d["status"], d["active_version_id"], d["version_count"]) == (
        "Sales 2026",
        "ACTIVE",
        None,
        0,
    )
    assert on.post("/datasets", headers=member, json={"name": "Nope"}).status_code == 403
    dup = on.post("/datasets", headers=owner, json={"name": "sales 2026"})
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "DATASET_NAME_TAKEN"

    assert [x["id"] for x in on.get("/datasets", headers=member).json()] == [d["id"]]
    assert on.get(f"/datasets/{d['id']}", headers=member).json()["name"] == "Sales 2026"
    assert on.get("/datasets?limit=101", headers=member).status_code == 422

    vid = _seed_version(pg_stack, m.tenant_id, d["id"])
    versions = on.get(f"/datasets/{d['id']}/versions", headers=member).json()
    assert [v["id"] for v in versions] == [vid]
    v = on.get(f"/datasets/{d['id']}/versions/{vid}", headers=member).json()
    assert v["status"] == "QUARANTINED" and v["original_filename"] == "sales.csv"
    assert not [k for k in v if "storage" in k or "key" in k or "url" in k or "path" in k]

    assert on.delete(f"/datasets/{d['id']}/versions/{vid}", headers=member).status_code == 403
    rv = on.delete(f"/datasets/{d['id']}/versions/{vid}", headers=admin)
    assert rv.status_code == 202 and rv.json()["status"] == "DELETING"
    assert on.delete(f"/datasets/{d['id']}/versions/{vid}", headers=admin).status_code == 202

    assert on.delete(f"/datasets/{d['id']}", headers=member).status_code == 403
    first = on.delete(f"/datasets/{d['id']}", headers=admin)
    second = on.delete(f"/datasets/{d['id']}", headers=owner)
    assert first.status_code == second.status_code == 202
    assert first.json()["deletion_requested_at"] == second.json()["deletion_requested_at"]
    assert second.json()["status"] == "DELETING"
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = c.execute(
            "SELECT count(*) FROM dataset_events WHERE dataset_id = %s "
            "AND event_type = 'DATASET_DELETION_REQUESTED'",
            (d["id"],),
        ).fetchone()
    assert n == (1,)


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"name": "evil‮name"}, "DATASET_NAME_INVALID"),
        ({"name": "a" * 101}, "DATASET_NAME_INVALID"),
        ({"name": "ok", "description": "x\x00y"}, "DATASET_DESCRIPTION_INVALID"),
        ({"name": "ok", "description": "d" * 501}, "DATASET_DESCRIPTION_INVALID"),
    ],
)
def test_hostile_metadata_gets_a_stable_422_code(
    on: TestClient, pg_stack: SimpleNamespace, body: dict[str, str], code: str
) -> None:
    m = pg_stack.seed_member("owner")
    r = on.post("/datasets", headers=_hdr(m.user_id, m.tenant_id), json=body)
    assert r.status_code == 422 and r.json()["error"]["code"] == code


@pytest.mark.parametrize(
    "extra",
    [
        {"tenant_id": str(uuid.uuid4())},
        {"status": "DELETED"},
        {"created_by": str(uuid.uuid4())},
        {"active_version_id": str(uuid.uuid4())},
        {"storage_object_key": "quarantine/x/y/z.csv"},
    ],
)
def test_server_owned_fields_are_refused(
    on: TestClient, pg_stack: SimpleNamespace, extra: dict[str, str]
) -> None:
    m = pg_stack.seed_member("owner")
    r = on.post("/datasets", headers=_hdr(m.user_id, m.tenant_id), json={"name": "x", **extra})
    assert r.status_code == 422


def test_other_workspace_ids_are_indistinguishable_from_missing(
    on: TestClient, pg_stack: SimpleNamespace
) -> None:
    a, b = pg_stack.seed_member("owner"), pg_stack.seed_member("owner")
    ha, hb = _hdr(a.user_id, a.tenant_id), _hdr(b.user_id, b.tenant_id)
    d = on.post("/datasets", headers=ha, json={"name": "Secret"}).json()
    vid = _seed_version(pg_stack, a.tenant_id, d["id"])
    missing = str(uuid.uuid4())
    for path in (f"/datasets/{d['id']}", f"/datasets/{missing}"):
        r = on.get(path, headers=hb)
        assert r.status_code == 404 and r.json()["error"]["code"] == "DATASET_NOT_FOUND"
    assert on.get(f"/datasets/{d['id']}/versions", headers=hb).status_code == 404
    assert on.get(f"/datasets/{d['id']}/versions/{vid}", headers=hb).status_code == 404
    assert on.delete(f"/datasets/{d['id']}", headers=hb).status_code == 404
    assert on.delete(f"/datasets/{d['id']}/versions/{vid}", headers=hb).status_code == 404
    assert on.get("/datasets", headers=hb).json() == []
    # B cannot borrow A's workspace header either.
    spoof = _hdr(b.user_id, a.tenant_id)
    assert on.get(f"/datasets/{d['id']}", headers=spoof).status_code == 403
    assert on.get(f"/datasets/{d['id']}", headers=ha).json()["status"] == "ACTIVE"


def test_tombstoned_dataset_is_gone_from_the_api(on: TestClient, pg_stack: SimpleNamespace) -> None:
    from nlw.ops import datasets as ops_datasets

    m = pg_stack.seed_member("owner")
    h = _hdr(m.user_id, m.tenant_id)
    d = on.post("/datasets", headers=h, json={"name": "Old"}).json()
    vid = _seed_version(pg_stack, m.tenant_id, d["id"])
    assert on.delete(f"/datasets/{d['id']}", headers=h).status_code == 202
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        ops_datasets.tombstone(c, dataset_id=uuid.UUID(d["id"]))
    assert on.get(f"/datasets/{d['id']}", headers=h).status_code == 404
    assert on.get(f"/datasets/{d['id']}/versions/{vid}", headers=h).status_code == 404
    assert on.delete(f"/datasets/{d['id']}", headers=h).status_code == 404
    assert on.get("/datasets", headers=h).json() == []
