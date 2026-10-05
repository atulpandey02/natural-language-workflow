"""Dataset upload, profiling, semantics and activation (ADR-030) through the real
app, auth, signed contexts, PostgreSQL, the local object store and the isolated
profiling process.

``TestClient`` completes background tasks before returning a response, so the
profile is ready (or the version rejected) when the content ``PUT`` returns:
the tests are deterministic, with no polling or sleeps.
"""

import hashlib
import json
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app

pytestmark = pytest.mark.integration

_SECRET = "dev-secret-for-tests-32bytes-min-length"
CSV = b"Region,Amount,Order Date,Customer Email\n" + b"".join(
    f"{['north', 'south', 'east'][i % 3]},{i * 2.5:.2f},2024-03-{(i % 28) + 1:02d},"
    f"buyer{i}@example.test\n".encode()
    for i in range(1, 61)
)
MAPPING = {
    "columns": [
        {"name": "region", "label": "Region", "semantic_type": "category",
         "role": "dimension", "analysis_allowed": True},
        {"name": "amount", "label": "Amount", "semantic_type": "currency",
         "role": "measure", "analysis_allowed": True},
        {"name": "order_date", "label": "Order date", "semantic_type": "date",
         "role": "timestamp", "analysis_allowed": True},
        {"name": "customer_email", "label": "Customer", "semantic_type": "contact",
         "role": "identifier", "analysis_allowed": False},
    ]
}  # fmt: skip


def _hdr(user_id: uuid.UUID, tenant_id: uuid.UUID, **extra: str) -> dict[str, str]:
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
    return {"Authorization": f"Bearer {token}", "X-Workspace-Id": str(tenant_id), **extra}


def _key() -> str:
    return uuid.uuid4().hex


@pytest.fixture
def store_root(tmp_path: Path) -> Path:
    return tmp_path / "datasets"


@pytest.fixture
def up(pg_stack: SimpleNamespace, store_root: Path) -> Iterator[TestClient]:
    settings = pg_stack.settings.model_copy(
        update={
            "datasets_api_enabled": True,
            "dataset_storage_backend": "local",
            "dataset_storage_root": str(store_root),
        }
    )
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def ws(pg_stack: SimpleNamespace) -> SimpleNamespace:
    m = pg_stack.seed_member("owner")
    return SimpleNamespace(
        tenant=m.tenant_id,
        owner=_hdr(m.user_id, m.tenant_id),
        admin=_hdr(pg_stack.add_membership(m.tenant_id, "admin"), m.tenant_id),
        member=_hdr(pg_stack.add_membership(m.tenant_id, "member"), m.tenant_id),
    )


def _dataset(c: TestClient, h: dict[str, str], name: str = "Sales") -> str:
    r = c.post("/datasets", headers=h, json={"name": name})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _initiate(
    c: TestClient, h: dict[str, str], did: str, data: bytes, key: str | None = None, **kw: Any
) -> Any:
    body = {"original_filename": kw.pop("filename", "sales.csv"),
            "declared_size_bytes": kw.pop("size", len(data))}  # fmt: skip
    return c.post(
        f"/datasets/{did}/versions",
        headers={**h, "Idempotency-Key": key or _key()},
        json=body,
    )


def _upload(c: TestClient, h: dict[str, str], did: str, data: bytes) -> dict[str, Any]:
    r = _initiate(c, h, did, data)
    assert r.status_code == 201, r.text
    vid = r.json()["id"]
    put = c.put(
        f"/datasets/{did}/versions/{vid}/content",
        headers={**h, "Content-Type": "text/csv"},
        content=data,
    )
    assert put.status_code == 202, put.text
    v = c.get(f"/datasets/{did}/versions/{vid}", headers=h).json()
    assert isinstance(v, dict)
    return v


def _files(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def _events(pg: SimpleNamespace, vid: str) -> list[tuple[str, str | None, str, str | None]]:
    with psycopg.connect(pg.owner_libpq) as c:
        return [
            tuple(r)
            for r in c.execute(
                "SELECT event_type, from_status, to_status, reason_code FROM dataset_events "
                "WHERE version_id = %s ORDER BY created_at, event_type",
                (vid,),
            ).fetchall()
        ]


# --- routes exist only with a store -------------------------------------------------------


def test_upload_routes_need_the_flag_and_a_store(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member("owner")
    h = _hdr(m.user_id, m.tenant_id)
    flag_only = pg_stack.settings.model_copy(update={"datasets_api_enabled": True})
    with TestClient(create_app(flag_only)) as c:
        did = _dataset(c, h)
        assert _initiate(c, h, did, CSV).status_code == 405  # metadata route, no POST
        put = c.put(f"/datasets/{did}/versions/{uuid.uuid4()}/content", headers=h, content=CSV)
        assert put.status_code in (404, 405)
        # Without the upload route the content path is NOT exempt from the 1 MB cap.
        big = c.put(
            f"/datasets/{did}/versions/{uuid.uuid4()}/content",
            headers=h,
            content=b"x" * 1_000_001,
        )
        assert big.status_code == 413


# --- the happy path ---------------------------------------------------------------------


def test_upload_profile_confirm_activate(
    up: TestClient, ws: SimpleNamespace, pg_stack: SimpleNamespace, store_root: Path
) -> None:
    did = _dataset(up, ws.admin)
    r = _initiate(up, ws.admin, did, CSV)
    assert r.status_code == 201, r.text
    created = r.json()
    assert (created["status"], created["has_content"], created["content_sha256"]) == (
        "QUARANTINED",
        False,
        None,
    )
    vid = created["id"]
    put = up.put(
        f"/datasets/{did}/versions/{vid}/content",
        headers={**ws.admin, "Content-Type": "text/csv"},
        content=CSV,
    )
    assert put.status_code == 202, put.text
    v = up.get(f"/datasets/{did}/versions/{vid}", headers=ws.member).json()
    assert v["status"] == "PROFILED" and v["has_content"] is True
    assert v["content_sha256"] == hashlib.sha256(CSV).hexdigest()

    profile = up.get(f"/datasets/{did}/versions/{vid}/profile", headers=ws.admin)
    assert profile.status_code == 200
    p = profile.json()
    assert (p["contract_version"], p["row_count"], p["column_count"]) == ("profile-2", 60, 4)
    assert [c["name"] for c in p["columns"]] == [c["name"] for c in MAPPING["columns"]]
    assert "possible_email" in p["columns"][3]["indicators"]
    assert "buyer1@example.test" not in json.dumps(p)  # no sample or bound for that column

    # Members never see profiles or semantics, and cannot confirm or activate.
    assert up.get(f"/datasets/{did}/versions/{vid}/profile", headers=ws.member).status_code == 403
    assert (
        up.post(f"/datasets/{did}/versions/{vid}/semantics", headers=ws.member, json=MAPPING)
    ).status_code == 403
    assert up.post(f"/datasets/{did}/versions/{vid}/activate", headers=ws.member).status_code == 403

    early = up.post(f"/datasets/{did}/versions/{vid}/activate", headers=ws.admin)
    assert early.status_code == 409
    assert early.json()["error"]["code"] == "SEMANTICS_NOT_CONFIRMED"

    sem = up.post(f"/datasets/{did}/versions/{vid}/semantics", headers=ws.admin, json=MAPPING)
    assert sem.status_code == 201, sem.text
    assert sem.json()["revision_number"] == 1
    act = up.post(f"/datasets/{did}/versions/{vid}/activate", headers=ws.owner)
    assert act.status_code == 200 and act.json()["status"] == "ACTIVE"
    ds = up.get(f"/datasets/{did}", headers=ws.member).json()
    assert ds["active_version_id"] == vid

    assert [e[:3] for e in _events(pg_stack, vid)] == [
        ("VERSION_CREATED", None, "QUARANTINED"),
        ("VERSION_PROFILING_STARTED", "QUARANTINED", "PROFILING"),
        ("VERSION_PROFILED", "PROFILING", "PROFILED"),
        ("VERSION_ACTIVATED", "PROFILED", "ACTIVE"),
    ]
    # Published under datasets/, quarantine copy removed; nothing else on disk.
    assert _files(store_root / "local") == [f"datasets/{ws.tenant}/{did}/{vid}"]
    # No response ever carries a storage key, area or path.
    for body in (created, put.json(), v, p, sem.json(), act.json(), ds):
        text = json.dumps(body)
        assert "quarantine/" not in text and "datasets/" not in text
        assert str(store_root) not in text and "storage_object_key" not in text


def test_a_new_upload_supersedes_the_active_version(up: TestClient, ws: SimpleNamespace) -> None:
    did = _dataset(up, ws.admin)
    first = _upload(up, ws.admin, did, CSV)
    up.post(f"/datasets/{did}/versions/{first['id']}/semantics", headers=ws.admin, json=MAPPING)
    up.post(f"/datasets/{did}/versions/{first['id']}/activate", headers=ws.admin)
    second = _upload(up, ws.admin, did, CSV + b"west,1.00,2024-04-01,late@example.test\n")
    assert second["version_number"] == 2 and second["status"] == "PROFILED"
    up.post(f"/datasets/{did}/versions/{second['id']}/semantics", headers=ws.admin, json=MAPPING)
    assert (
        up.post(f"/datasets/{did}/versions/{second['id']}/activate", headers=ws.admin).json()[
            "status"
        ]
        == "ACTIVE"
    )
    old = up.get(f"/datasets/{did}/versions/{first['id']}", headers=ws.admin).json()
    assert old["status"] == "SUPERSEDED"


# --- idempotency and concurrency ------------------------------------------------------------


def test_initiation_is_idempotent_per_key(up: TestClient, ws: SimpleNamespace) -> None:
    did = _dataset(up, ws.admin)
    key = _key()
    a = _initiate(up, ws.admin, did, CSV, key)
    b = _initiate(up, ws.admin, did, CSV, key)
    assert a.status_code == b.status_code == 201 and a.json()["id"] == b.json()["id"]
    reused = _initiate(up, ws.admin, did, CSV, key, filename="other.csv")
    assert reused.status_code == 409
    assert reused.json()["error"]["code"] == "IDEMPOTENCY_KEY_REUSED"
    missing = up.post(
        f"/datasets/{did}/versions",
        headers=ws.admin,
        json={"original_filename": "a.csv", "declared_size_bytes": 10},
    )
    assert missing.status_code == 400
    assert missing.json()["error"]["code"] == "IDEMPOTENCY_KEY_REQUIRED"
    bad = _initiate(up, ws.admin, did, CSV, "short")
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "IDEMPOTENCY_KEY_INVALID"
    versions = up.get(f"/datasets/{did}/versions", headers=ws.admin).json()
    assert [v["version_number"] for v in versions] == [1]


def test_concurrent_initiations_with_one_key_create_one_version(
    up: TestClient, ws: SimpleNamespace
) -> None:
    did = _dataset(up, ws.admin)
    key = _key()
    ids: list[str] = []
    errors: list[int] = []

    def go() -> None:
        r = _initiate(up, ws.admin, did, CSV, key)
        (ids.append(r.json()["id"]) if r.status_code == 201 else errors.append(r.status_code))

    threads = [threading.Thread(target=go) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and len(set(ids)) == 1 and len(ids) == 6
    assert len(up.get(f"/datasets/{did}/versions", headers=ws.admin).json()) == 1


def test_concurrent_distinct_initiations_get_distinct_numbers(
    up: TestClient, ws: SimpleNamespace
) -> None:
    did = _dataset(up, ws.admin)
    numbers: list[int] = []

    def go() -> None:
        r = _initiate(up, ws.admin, did, CSV)
        assert r.status_code == 201
        numbers.append(r.json()["version_number"])

    threads = [threading.Thread(target=go) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(numbers) == [1, 2, 3, 4, 5, 6]


def test_content_is_write_once_and_retries_are_idempotent(
    up: TestClient, ws: SimpleNamespace, store_root: Path
) -> None:
    did = _dataset(up, ws.admin)
    v = _upload(up, ws.admin, did, CSV)
    url = f"/datasets/{did}/versions/{v['id']}/content"
    again = up.put(url, headers=ws.admin, content=CSV)
    assert again.status_code == 202 and again.json()["id"] == v["id"]
    tampered = CSV[:-2] + b"9\n"
    other = up.put(url, headers=ws.admin, content=tampered)
    assert other.status_code == 409 and other.json()["error"]["code"] == "CONTENT_CONFLICT"
    stored = store_root / "local" / "datasets" / str(ws.tenant) / did / v["id"]
    assert stored.read_bytes() == CSV  # the stored version was never altered


def test_content_must_be_exactly_the_declared_size(
    up: TestClient, ws: SimpleNamespace, store_root: Path
) -> None:
    did = _dataset(up, ws.admin)
    vid = _initiate(up, ws.admin, did, CSV, size=len(CSV) + 10).json()["id"]
    short = up.put(f"/datasets/{did}/versions/{vid}/content", headers=ws.admin, content=CSV)
    assert short.status_code == 422
    assert short.json()["error"]["code"] == "CONTENT_SIZE_MISMATCH"
    vid2 = _initiate(up, ws.admin, did, CSV, size=len(CSV) - 10).json()["id"]
    long = up.put(f"/datasets/{did}/versions/{vid2}/content", headers=ws.admin, content=CSV)
    assert long.status_code == 413
    assert _files(store_root / "local") == []  # nothing left behind
    for x in (vid, vid2):
        got = up.get(f"/datasets/{did}/versions/{x}", headers=ws.admin).json()
        assert (got["status"], got["has_content"]) == ("QUARANTINED", False)


def test_a_declared_length_over_the_limit_is_refused_before_reading(
    up: TestClient, ws: SimpleNamespace
) -> None:
    did = _dataset(up, ws.admin)
    vid = _initiate(up, ws.admin, did, CSV).json()["id"]
    r = up.put(
        f"/datasets/{did}/versions/{vid}/content",
        headers={**ws.admin, "Content-Length": "25000001"},
        content=CSV,
    )
    assert r.status_code == 413
    too_big = _initiate(up, ws.admin, did, CSV, size=25_000_001)
    assert too_big.status_code == 422


# --- invalid files ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data,code",
    [
        (b"a,a\n1,2\n", "HEADER_DUPLICATE"),
        (b"a,b\n1\n", "ROW_WIDTH_MISMATCH"),
        (b"a,b\n", "NO_DATA_ROWS"),
        (b"PK\x03\x04" + b"\x00" * 30, "FILE_TYPE"),
        ("a,b\né,1\n".encode("cp1252"), "ENCODING_UNSUPPORTED"),
    ],
)
def test_invalid_files_are_rejected_and_their_bytes_removed(
    up: TestClient,
    ws: SimpleNamespace,
    pg_stack: SimpleNamespace,
    store_root: Path,
    data: bytes,
    code: str,
) -> None:
    did = _dataset(up, ws.admin)
    v = _upload(up, ws.admin, did, data)
    assert (v["status"], v["rejection_code"]) == ("REJECTED", code)
    assert _events(pg_stack, v["id"])[-1] == ("VERSION_REJECTED", "PROFILING", "REJECTED", code)
    assert _files(store_root / "local") == []
    base = f"/datasets/{did}/versions/{v['id']}"
    assert up.get(f"{base}/profile", headers=ws.admin).status_code == 404
    act = up.post(f"{base}/activate", headers=ws.admin)
    assert act.status_code == 409
    sem = up.post(f"{base}/semantics", headers=ws.admin, json=MAPPING)
    assert sem.status_code == 409
    ds = up.get(f"/datasets/{did}", headers=ws.admin).json()
    assert ds["active_version_id"] is None  # malformed input never looks active


def test_content_type_is_not_trusted(up: TestClient, ws: SimpleNamespace) -> None:
    did = _dataset(up, ws.admin)
    vid = _initiate(up, ws.admin, did, CSV).json()["id"]
    r = up.put(
        f"/datasets/{did}/versions/{vid}/content",
        headers={**ws.admin, "Content-Type": "image/png"},
        content=CSV,
    )
    assert r.status_code == 202
    assert up.get(f"/datasets/{did}/versions/{vid}", headers=ws.admin).json()["status"] == (
        "PROFILED"
    )
    zipped = b"PK\x03\x04" + b"\x00" * 40
    vid2 = _initiate(up, ws.admin, did, zipped).json()["id"]
    up.put(
        f"/datasets/{did}/versions/{vid2}/content",
        headers={**ws.admin, "Content-Type": "text/csv"},
        content=zipped,
    )
    got = up.get(f"/datasets/{did}/versions/{vid2}", headers=ws.admin).json()
    assert (got["status"], got["rejection_code"]) == ("REJECTED", "FILE_TYPE")


# --- semantics ------------------------------------------------------------------------------


def test_semantics_are_validated_and_revisions_kept(up: TestClient, ws: SimpleNamespace) -> None:
    did = _dataset(up, ws.admin)
    v = _upload(up, ws.admin, did, CSV)
    base = f"/datasets/{did}/versions/{v['id']}"
    bad = json.loads(json.dumps(MAPPING))
    bad["columns"][3]["analysis_allowed"] = True
    bad["columns"][3]["role"] = "attribute"
    r = up.post(f"{base}/semantics", headers=ws.admin, json=bad)
    assert r.status_code == 422 and r.json()["error"]["code"] == "SEMANTICS_SENSITIVE_COLUMN"
    extra = json.loads(json.dumps(MAPPING))
    extra["columns"][0]["sql"] = "DROP TABLE x"
    assert up.post(f"{base}/semantics", headers=ws.admin, json=extra).status_code == 422
    for _ in range(2):
        assert up.post(f"{base}/semantics", headers=ws.admin, json=MAPPING).status_code == 201
    revs = up.get(f"{base}/semantics", headers=ws.admin).json()
    assert [r["revision_number"] for r in revs] == [1, 2]
    assert up.get(f"{base}/semantics", headers=ws.member).status_code == 403


# --- authentication, authorization, tenancy ---------------------------------------------------


def test_authentication_and_roles_are_enforced(
    up: TestClient, ws: SimpleNamespace, pg_stack: SimpleNamespace
) -> None:
    did = _dataset(up, ws.admin)
    vid = _initiate(up, ws.admin, did, CSV).json()["id"]
    url = f"/datasets/{did}/versions/{vid}/content"
    assert up.put(url, content=CSV, headers={"X-Workspace-Id": str(ws.tenant)}).status_code == 401
    assert up.put(url, content=CSV, headers=ws.member).status_code == 403
    assert _initiate(up, ws.member, did, CSV).status_code == 403
    outsider = pg_stack.seed_member("owner")
    not_member = _hdr(outsider.user_id, ws.tenant)
    assert up.put(url, content=CSV, headers=not_member).status_code == 403
    bad_ws = {**ws.admin, "X-Workspace-Id": "not-a-uuid"}
    assert up.put(url, content=CSV, headers=bad_ws).status_code == 400


def test_another_workspace_cannot_reach_a_version(
    up: TestClient, ws: SimpleNamespace, pg_stack: SimpleNamespace, store_root: Path
) -> None:
    did = _dataset(up, ws.admin)
    v = _upload(up, ws.admin, did, CSV)
    other = pg_stack.seed_member("owner")
    b = _hdr(other.user_id, other.tenant_id)
    base = f"/datasets/{did}/versions/{v['id']}"
    for method, path, kw in (
        ("get", base, {}),
        ("get", f"{base}/profile", {}),
        ("get", f"{base}/semantics", {}),
        ("post", f"{base}/semantics", {"json": MAPPING}),
        ("post", f"{base}/activate", {}),
        ("post", f"{base}/process", {}),
        ("post", f"/datasets/{did}/versions", {"json": {"original_filename": "x.csv",
                                                         "declared_size_bytes": 3},
                                                "headers": {**b, "Idempotency-Key": _key()}}),
        ("put", f"{base}/content", {"content": CSV}),
    ):  # fmt: skip
        headers = kw.pop("headers", b)
        r = getattr(up, method)(path, headers=headers, **kw)
        assert r.status_code == 404, (method, path, r.status_code)
    # The same user as an owner of BOTH workspaces, signed into B: still 404.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,'owner')",
            (uuid.uuid4(), other.user_id, ws.tenant),
        )
    assert up.get(f"{base}/profile", headers=b).status_code == 404
    assert up.get(f"{base}/profile", headers=_hdr(other.user_id, ws.tenant)).status_code == 200
    assert _files(store_root / "local") == [f"datasets/{ws.tenant}/{did}/{v['id']}"]


def test_deleting_makes_a_version_unusable_at_once(up: TestClient, ws: SimpleNamespace) -> None:
    did = _dataset(up, ws.admin)
    v = _upload(up, ws.admin, did, CSV)
    base = f"/datasets/{did}/versions/{v['id']}"
    up.post(f"{base}/semantics", headers=ws.admin, json=MAPPING)
    up.post(f"{base}/activate", headers=ws.admin)
    assert up.delete(f"/datasets/{did}", headers=ws.admin).status_code == 202
    assert up.delete(f"/datasets/{did}", headers=ws.admin).status_code == 202  # idempotent
    got = up.get(base, headers=ws.admin).json()
    assert got["status"] == "DELETING"
    assert up.get(f"{base}/profile", headers=ws.admin).status_code == 404
    assert up.post(f"{base}/activate", headers=ws.admin).status_code == 409
    new = _initiate(up, ws.admin, did, CSV)
    assert new.status_code == 409 and new.json()["error"]["code"] == "DATASET_NOT_ACTIVE"


# --- logging --------------------------------------------------------------------------------


def test_logs_never_carry_cell_values_filenames_or_keys(
    up: TestClient, ws: SimpleNamespace, capfd: pytest.CaptureFixture[str], caplog: Any
) -> None:
    canary = "zz-cell-canary-5b7e"
    data = b"note,n\n" + b"".join(f"{canary}{i},{i}\n".encode() for i in range(20))
    bad = b"note,n\n" + f"{canary},1,extra\n".encode()
    did = _dataset(up, ws.admin)
    for content, filename in ((data, "canary-file-name.csv"), (bad, "canary-file-name-2.csv")):
        vid = _initiate(up, ws.admin, did, content, filename=filename).json()["id"]
        up.put(f"/datasets/{did}/versions/{vid}/content", headers=ws.admin, content=content)
    out, err = capfd.readouterr()
    logs = out + err + caplog.text
    assert "dataset.version_profiled" in logs or "dataset.content_stored" in logs
    assert canary not in logs
    assert "canary-file-name" not in logs
    assert "quarantine/" not in logs and "datasets/" + str(ws.tenant) not in logs
