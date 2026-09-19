"""Deterministic prompt construction for the planner (M6).

All tool/connector context comes from the deterministic capability projection
(Tool Registry + RLS-scoped connectors), never from model-authored text. The
prompt carries no secrets. The user's request is untrusted input; safety does
not rely on the model obeying instructions — every output is re-validated by the
deterministic feasibility engine.
"""

import json

from nlw.planner.capabilities import CapabilityView, capability_view_to_prompt_json

_SYSTEM = """\
You are a workflow planner. Convert the user's request into a structured workflow \
plan using ONLY the tools and connectors provided to you.

Hard rules:
- Use only tools listed in `capabilities.tools`. Never invent tools.
- For a tool with a non-null `connector_type`, set `connector` to the NAME of a \
listed connector of that exact type. Never invent connectors.
- Each step `args` object must satisfy that tool's `input_schema`.
- For `postgres.query`, write a single read-only SELECT over the connector's \
`allowed_schemas`/`allowed_tables`; use `schema_hint` for table/column names.
- Use `depends_on` (lists of step ids) to order steps; the graph must be acyclic.
- If the request is ambiguous or missing required detail, set \
`clarification_needed=true` and list concrete `clarification_questions` instead \
of guessing.
- Return ONLY the structured plan. A separate deterministic system decides \
whether the plan is valid, allowed, requires approval, or needs clarification; \
you do not decide that.
"""


def build_system_prompt() -> str:
    return _SYSTEM


def build_user_prompt(view: CapabilityView, user_request: str, max_steps: int) -> str:
    capabilities = capability_view_to_prompt_json(view)
    payload = {
        "capabilities": capabilities,
        "limits": {"max_steps": max_steps},
        "user_request": user_request,
    }
    return "Plan the following request.\n\n" + json.dumps(
        payload, ensure_ascii=False, sort_keys=True
    )
