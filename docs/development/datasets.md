# Datasets (Phase 2 B04) — development notes

Status: **library layer only.** Nothing here is reachable from the API, the
worker, the planner or any model call. The first PR's database, API, ingestion
worker and UI are not implemented yet (see "Remaining" below).

## What exists

| Module | Purpose |
|---|---|
| `nlw.storage.blob` | `BlobStore` protocol, `LocalBlobStore` (dev/CI), `TenantScopedBlobStore` (derives keys server-side as `{quarantine\|datasets}/{tenant}/{dataset}/{object}`, refuses traversal and any key outside the bound tenant before the backing store is touched, verified per-dataset deletion). |
| `nlw.ingest.validate` | Stable reject codes; magic-byte refusal (zip/xlsx, PDF, OLE, ELF, PE, gzip/bzip2/xz/7z/rar, images, Parquet/Arrow, SQLite); NUL bytes refused unless UTF-16 BOM; encoding detection (UTF-8 with/without BOM, UTF-16 with BOM accepted; Windows-1252 accepted only with user confirmation; UTF-32 refused); control-character and line-length checks. |
| `nlw.ingest.schema` | `profile-1` Pydantic contract (`extra="forbid"`): a flagged column carries no samples and no min/max; samples only for columns with ≤ 50 distinct values, ≤ 10 values, ≤ 32 chars each. |
| `nlw.ingest.profile` | Deterministic, bounded profiler: byte/row/column/field/time limits; delimiter sniffing among `, ; \t \|`; header detection and normalisation (snake_case, ASCII fold, leading-digit prefix, ≤ 63 chars, duplicate suffixes); null tokens; type inference at ≥ 98 % (slash dates are never guessed); formula-prefix census; deterministic sensitivity detectors (header keywords; SSN, Luhn card, email, phone, ZIP+4 values; high-cardinality free text). SSN and card are `EXCLUDE` with `hard=true`. |

Boundary regressions (`tests/unit/test_phase2_model_boundary.py`): the planning
path imports neither package; the ingestion packages import no planner,
feasibility, registry, tool, connector, engine, API, database, provider, HTTP,
socket or query-engine module; the registry offers no `dataset*` tool; profiling
runs with sockets disabled.

## Implementation decisions

- **Profiler engine.** The plan specifies DuckDB `read_csv` in a sandboxed
  connection. DuckDB and pyarrow are new runtime dependencies awaiting owner
  approval (plan §22), so the profiler uses the standard-library `csv` module
  under the same limits. `profile_csv` is the single entry point; swapping the
  engine must keep the `profile-1` contract and the golden tests.
- **No S3 adapter.** No S3 client is in `uv.lock`; adding one needs the same
  approval and an ADR. `LocalBlobStore` covers development and CI.

## Route-scoped upload body limit (plan §0.8 item 5) — established

Checked against the pinned versions (`uv.lock`: Starlette 1.6.0, FastAPI
0.141.1) by experiment on 2026-09-29:

- Starlette 1.6.0 `Route`, `Mount` and `Router` accept `max_body_size`
  (wrapping `RequestBodyLimitMiddleware`, enforced on streamed bytes and on an
  honest `Content-Length`; a chunked 20-byte body against a 10-byte cap
  returned 413).
- FastAPI 0.141.1 `APIRoute` / `add_api_route` do **not** accept
  `max_body_size`; wrapping a registered `APIRoute.app` in
  `RequestBodyLimitMiddleware` works.
- NLW's own outermost `BodySizeLimitMiddleware` (`nlw.api.middleware`, default
  1 MB) drains and buffers the whole body **before routing**, so no
  route-level setting can raise the limit for one route.

Consequence for the upload route: exempt exactly that path in
`BodySizeLimitMiddleware` (streaming it through unbuffered) and enforce the
25 MB cap in the route with a streaming reader that writes to quarantine and
aborts with 413 past the cap (`LocalBlobStore.put_stream(max_bytes=...)`
already leaves no object behind on overflow). This is the "route-scoped
streaming cap" alternative in plan §21.

## Remaining for the first PR (in dependency order)

1. Owner decisions: dependency approval (DuckDB/pyarrow, S3 client),
   deletion statement (plan §0.6), named operator.
2. Migration: `datasets`, `dataset_uploads`, `dataset_profiles`, a
   tombstone table; RLS (update `EXPECTED_SIGNED_POLICIES` in all three
   places); `nlw_ingest` role in `docker/postgres/initdb/00-roles.sh` and
   `nlw.ops.roles`; `ingest_execution` purpose in `nlw.tenancy.signing` and the
   verifier's purpose→role map; ingest key class for `nlw.ctxkeys`.
3. API: `POST/GET /datasets`, `POST /datasets/{id}/uploads` (streaming cap
   above), `GET /uploads/{id}`, `GET /uploads/{id}/profile`,
   `DELETE /datasets/{id}` behind `DATASETS_ENABLED`; audit events.
4. Ingestion actor on queue `ingest` (idempotent per upload, 3 attempts,
   stuck gauge), Compose service and rollout `validate` checks.
5. Web: datasets pages, dropzone, profile table; Playwright journey.
