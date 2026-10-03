# Evidence — Phase 2A dataset lifecycle foundation (ADR-029)

Branch `feat/phase2-dataset-lifecycle`, from `main` at `9972830`. Local
evidence gathered 2026-10-03 on PostgreSQL 16 testcontainers. CI evidence is
on the pull request. Nothing here was merged, deployed, or run against staging.

## Scope

**In scope:**

- dataset and version metadata;
- lifecycle states;
- authorization;
- tenant isolation;
- the append-only lifecycle events;
- deletion requests and the operator tombstone.

**Out of scope (absent by design):**

- upload;
- any customer file or object;
- object-storage writes;
- profile persistence;
- planner or model access;
- analytical query execution;
- DuckDB;
- UI.

The metadata API is mounted only with `DATASETS_API_ENABLED=true`, which
staging and production refuse.

## Invariants and where they are proven

| Invariant | Enforced by | Proven by |
|---|---|---|
| Tenant isolation | forced RLS on the signed context; composite tenant FKs; service `tenant_id` predicates | `test_dataset_lifecycle_db.py::test_tenant_b_cannot_see_or_touch_tenant_a`, `test_dataset_service.py::test_member_cannot_write_and_other_tenant_cannot_see`, `test_datasets_api.py::test_other_workspace_ids_are_indistinguishable_from_missing` |
| Explicit transitions only | `dataset_version_guard` / `dataset_guard` triggers; Python table equal to the trigger's | every-pair unit test; ≥ 30 invalid transitions refused by the database; service-level conflicts |
| Nothing leaves `DELETED` | terminal guard in both triggers; RLS `WITH CHECK status <> 'DELETED'`; row-shape CHECKs | `test_deleted_is_terminal_even_for_the_table_owner` (pinned to the guard), app-role tombstone tests, `test_operator_tombstone_scrubs_and_never_resurrects` |
| At most one ACTIVE version; pointer agrees | partial unique index; deferred consistency trigger; dataset row lock | `test_at_most_one_active_version_and_the_pointer_must_agree`, `test_concurrent_activation_leaves_exactly_one_active_version` |
| Unique, consecutive version numbers | atomic counter `UPDATE … RETURNING`; insert guard | `test_concurrent_version_creation_allocates_unique_consecutive_numbers` (8 concurrent) |
| Versions immutable | trigger: identity, size, media type, filename, digest/key set once | DB immutability tests |
| Deletion blocks use | DELETING dataset accepts no version, transition or activation; consistency trigger | `test_dataset_deletion_is_idempotent_and_blocks_everything_after`, concurrent delete-vs-activate test |
| Audit trail | one `dataset_events` row per transition; INSERT/SELECT only for `nlw_app`; no runtime DELETE/UPDATE | event-sequence assertions; grant tests |
| Least privilege | grants to `nlw_app` only; worker/scheduler/PUBLIC none; no SECURITY DEFINER; `search_path = pg_catalog` | role-matrix and catalogue tests |
| Bounded metadata | normalizers + DB CHECKs; `extra="forbid"` contracts; no JSON/bytea column | unit hostile-input tests; API 422 codes; catalogue test |
| No planner exposure | no import path; no dataset tool or capability | `test_phase2_model_boundary.py` |
| Product honesty | flag default off, refused in staging/production; routes absent when off | unit config tests; `test_flag_off_mounts_no_dataset_route` |
| Safe migration | `0024` only adds objects; single head | `test_phase2_migration_reversibility.py` (up/down/up; populated 0023 → 0024 preserves data) |

## Mutation and negative controls

Each mutation was applied to an isolated copy of the tree, the dataset suites
were run, and then the mutation was restored (byte-identical, checked by `diff`).

| Mutation | Result |
|---|---|
| Member SELECT policy loses its tenant/membership predicate (`true`) | **2 failed**: DB tenant-B isolation, service cross-tenant test |
| Migration allows `QUARANTINED → PROFILED / ACTIVE` | **2 failed**: unit parity with the trigger table, DB invalid-transition test |
| Terminal `DELETED` guard removed from both triggers | **1 failed**: `test_deleted_is_terminal_even_for_the_table_owner` |
| One-ACTIVE unique index made non-unique **and** the consistency trigger's count check removed | **1 failed**: `test_at_most_one_active_version_and_the_pointer_must_agree` |
| Every policy keeps the membership check but loses its signed-tenant binding (`tenant_id = ctx_tenant_id()`) | **1 failed**: `test_policies_bind_to_the_signed_tenant_not_just_membership` (reads) — added after review; before it, **all 74 dataset tests passed** under this mutation |
| Only the INSERT/UPDATE (admin) policies lose the signed-tenant binding | **1 failed**: the same test (forged inserts into the other workspace) |
| Events INSERT policy loses `actor_kind <> 'operator' AND to_status <> 'DELETED'` | **1 failed**: `test_runtime_app_role_cannot_forge_tombstone_or_operator_events` — added after review; nothing caught it before |
| Service drops `tenant_id = :t` from a statement (module constant, or inline `text()`) | **1 failed**: unit `test_every_service_statement_is_scoped_to_the_callers_tenant` — with RLS intact no integration test can see this layer, so it is pinned statically |

The first terminal-guard mutation run also allowed `DELETED → DELETING/ACTIVE`
in the transition table. Only the parity test failed, because the row-shape
CHECK constraints still refused every resurrection. The terminal test was then
pinned to the guard's own error, and the guard-only mutation was rerun. The
result is the one in the table above.

Review finding (PR #46): the original tenant tests used a user who belonged
to only one workspace, so they could not tell the signed-tenant binding apart
from the membership check. A user who belongs to two workspaces, with the
binding removed, could read and write the other workspace's rows, and no test
failed. The regression test uses one user who owns both workspaces and signs
into the wrong one.

The API cross-tenant test stays green under the RLS mutation, by design: the
service's own `tenant_id` predicates are a second, independent layer.

## Validation

| Check | Result |
|---|---|
| `ruff format --check`, `ruff check` | clean |
| `mypy` (342 files) | clean |
| `alembic heads` | single head `0024_dataset_lifecycle` |
| Unit suite | 1522 passed |
| New integration suites | lifecycle DB 47, service 16, API 13 — all pass |
| Full integration suite (excluding the browser harness, which CI runs) | 540 passed (25 min); dataset suites re-run on the final tree: 132 passed |
| `pip-audit` (CI's command) | no known vulnerabilities; `uv.lock`/`pyproject.toml` unchanged |
| Secret pattern scan of changed files | no findings in this diff |
| `git diff --check` | clean |

## Not done (owner decisions / later work)

- Retention periods for tombstones and events are pilot proposals.
- The external deletion log is a launch gate.
- Not built yet:
  - the ingest role and purpose;
  - upload and physical object deletion;
  - profiles;
  - UI.
