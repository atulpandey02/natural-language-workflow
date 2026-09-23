"""Deterministic AI evaluation harness (M12B-A, Part B).

A versioned corpus of synthetic, non-secret cases graded against the REAL tool
registry and the REAL deterministic feasibility engine. Two modes:

- ``replay``  — checked-in planner-output fixtures through ``check_plan``; zero
  LLM/network. This is what ordinary CI runs and what proves the acceptance
  criteria (no invalid/adversarial plan reaches execution).
- ``live``    — optional, credential-gated: the actual planner is run and its
  structured result graded deterministically. It never executes a plan, so no
  external side effect can occur. Off in ordinary CI.
"""
