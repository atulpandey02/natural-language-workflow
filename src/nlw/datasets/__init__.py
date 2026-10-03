"""Dataset lifecycle foundation (Phase 2A, ADR-029): metadata only.

Deterministic, tenant-scoped records of datasets and their immutable versions.
No file bytes, rows, uploads, storage access, profiling execution, planner
visibility or query execution live here. Nothing on the planning path may
import this package (``tests/unit/test_phase2_model_boundary.py``).
"""
