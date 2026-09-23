"""Deterministic feasibility engine (M6).

Pure Python. Given a proposed plan, the tenant capability view, and platform
limits, it decides the FINAL status — PASS / REJECT / NEEDS_CLARIFICATION /
NEEDS_APPROVAL — with an explicit, machine-readable finding list. The LLM never
determines this. A plan is not executable merely because it parsed; it must
survive every stage here.

Stages: structural -> tool availability -> connector compatibility -> argument
validation -> SQL safety (M5 validator) -> DAG -> limits -> approval/clarification.
"""

import enum
import json
from typing import Any

from pydantic import BaseModel, ValidationError

from nlw.domain.workflow import WorkflowPlan, WorkflowStep
from nlw.feasibility.limits import PlatformLimits
from nlw.feasibility.sql_safety import SqlSafetyError, validate_select
from nlw.planner.capabilities import CapabilityView, SafeConnector, ToolCapability

_POSTGRES_QUERY_TOOL = "postgres.query"


class FeasibilityStatus(enum.StrEnum):
    PASS = "PASS"
    REJECT = "REJECT"
    NEEDS_CLARIFICATION = "NEEDS_CLARIFICATION"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"


class Severity(enum.StrEnum):
    REJECT = "reject"
    CLARIFY = "clarify"
    APPROVE = "approve"
    INFO = "info"


class FeasibilityCode(enum.StrEnum):
    EMPTY_PLAN = "EMPTY_PLAN"
    TOO_MANY_STEPS = "TOO_MANY_STEPS"
    PLAN_TOO_LARGE = "PLAN_TOO_LARGE"
    ARGS_TOO_LARGE = "ARGS_TOO_LARGE"
    DUPLICATE_STEP_ID = "DUPLICATE_STEP_ID"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    TOOL_NOT_AVAILABLE = "TOOL_NOT_AVAILABLE"
    CONNECTOR_REQUIRED = "CONNECTOR_REQUIRED"
    CONNECTOR_NOT_FOUND = "CONNECTOR_NOT_FOUND"
    CONNECTOR_TYPE_MISMATCH = "CONNECTOR_TYPE_MISMATCH"
    CONNECTOR_UNUSABLE = "CONNECTOR_UNUSABLE"
    # The bound connector's execution-relevant configuration/destination changed
    # since materialization (identity binding, M12B final; see connector_binding).
    CONNECTOR_CONFIG_CHANGED = "CONNECTOR_CONFIG_CHANGED"
    CONNECTOR_ON_CONNECTORLESS_TOOL = "CONNECTOR_ON_CONNECTORLESS_TOOL"
    CONNECTOR_HEALTH_UNVERIFIED = "CONNECTOR_HEALTH_UNVERIFIED"
    ARG_VALIDATION_FAILED = "ARG_VALIDATION_FAILED"
    SQL_REJECTED = "SQL_REJECTED"
    UNKNOWN_DEPENDENCY = "UNKNOWN_DEPENDENCY"
    SELF_DEPENDENCY = "SELF_DEPENDENCY"
    TOO_MANY_DEPENDENCIES = "TOO_MANY_DEPENDENCIES"
    CYCLE_DETECTED = "CYCLE_DETECTED"
    STEP_TIMEOUT_EXCEEDED = "STEP_TIMEOUT_EXCEEDED"
    TOTAL_TIMEOUT_EXCEEDED = "TOTAL_TIMEOUT_EXCEEDED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    CLARIFICATION_REQUIRED = "CLARIFICATION_REQUIRED"
    PLANNER_INVALID_OUTPUT = "PLANNER_INVALID_OUTPUT"


class FeasibilityFinding(BaseModel):
    code: FeasibilityCode
    severity: Severity
    message: str
    step_id: str | None = None
    detail: dict[str, Any] | None = None


class FeasibilityReport(BaseModel):
    status: FeasibilityStatus
    findings: list[FeasibilityFinding]
    approvals_required: list[str] = []
    clarification_questions: list[str] = []
    # Canonical plan (e.g. re-rendered SQL); present only when status != REJECT.
    normalized_plan: WorkflowPlan | None = None


def _decide_status(findings: list[FeasibilityFinding], approvals: list[str]) -> FeasibilityStatus:
    """Deterministic precedence: reject > clarify > approve > pass."""
    if any(f.severity == Severity.REJECT for f in findings):
        return FeasibilityStatus.REJECT
    if any(f.severity == Severity.CLARIFY for f in findings):
        return FeasibilityStatus.NEEDS_CLARIFICATION
    if approvals:
        return FeasibilityStatus.NEEDS_APPROVAL
    return FeasibilityStatus.PASS


def planner_invalid_output_report(
    message: str = "planner produced invalid output",
) -> FeasibilityReport:
    """A deterministic REJECT for unparseable/invalid model output."""
    return FeasibilityReport(
        status=FeasibilityStatus.REJECT,
        findings=[
            FeasibilityFinding(
                code=FeasibilityCode.PLANNER_INVALID_OUTPUT,
                severity=Severity.REJECT,
                message=message,
            )
        ],
    )


def _validate_connector(
    step: WorkflowStep, tool: ToolCapability, view: CapabilityView
) -> tuple[SafeConnector | None, list[FeasibilityFinding]]:
    """Resolve and check the step's connector. Returns (connector, findings).
    The connector is returned only when it is resolved and type-compatible."""
    findings: list[FeasibilityFinding] = []
    if tool.connector_type is None:
        if step.connector is not None:
            findings.append(
                FeasibilityFinding(
                    code=FeasibilityCode.CONNECTOR_ON_CONNECTORLESS_TOOL,
                    severity=Severity.REJECT,
                    message=f"tool '{tool.name}' takes no connector",
                    step_id=step.id,
                )
            )
        return None, findings

    if step.connector is None:
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.CONNECTOR_REQUIRED,
                severity=Severity.REJECT,
                message=f"tool '{tool.name}' requires a connector of type '{tool.connector_type}'",
                step_id=step.id,
            )
        )
        return None, findings

    connector = view.connector(step.connector)
    if connector is None:
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.CONNECTOR_NOT_FOUND,
                severity=Severity.REJECT,
                message=f"connector '{step.connector}' not found for this tenant",
                step_id=step.id,
            )
        )
        return None, findings

    if connector.type != tool.connector_type:
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.CONNECTOR_TYPE_MISMATCH,
                severity=Severity.REJECT,
                message=(
                    f"connector '{connector.name}' is type '{connector.type}', "
                    f"tool needs '{tool.connector_type}'"
                ),
                step_id=step.id,
            )
        )
        return None, findings

    if connector.status == "disabled":
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.CONNECTOR_UNUSABLE,
                severity=Severity.REJECT,
                message=f"connector '{connector.name}' is disabled",
                step_id=step.id,
            )
        )
        return None, findings

    if connector.status == "error":
        # M4 makes 'error' recoverable: the worker re-health-checks before use.
        # Do not block planning; surface an informational finding only.
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.CONNECTOR_HEALTH_UNVERIFIED,
                severity=Severity.INFO,
                message=f"connector '{connector.name}' is in error state; re-checked at run",
                step_id=step.id,
            )
        )

    return connector, findings


def _validate_args(
    step: WorkflowStep, tool: ToolCapability
) -> tuple[bool, FeasibilityFinding | None]:
    try:
        tool.input_model.model_validate(step.args)
        return True, None
    except ValidationError as exc:
        return False, FeasibilityFinding(
            code=FeasibilityCode.ARG_VALIDATION_FAILED,
            severity=Severity.REJECT,
            message=f"arguments for '{tool.name}' failed validation",
            step_id=step.id,
            detail={"error_count": exc.error_count()},
        )


def _validate_sql(
    step: WorkflowStep, connector: SafeConnector
) -> tuple[str | None, FeasibilityFinding | None]:
    """Validate postgres.query SQL with the M5 validator. Returns (rendered, finding)."""
    sql = step.args.get("sql")
    if not isinstance(sql, str):
        # Arg validation already guarantees a str; defensive only.
        return None, None
    schemas = connector.allowed_schemas or []
    tables = connector.allowed_tables
    try:
        rendered = validate_select(sql, schemas, tables)
        return rendered, None
    except SqlSafetyError as exc:
        return None, FeasibilityFinding(
            code=FeasibilityCode.SQL_REJECTED,
            severity=Severity.REJECT,
            message=f"SQL rejected by safety policy: {exc}",
            step_id=step.id,
        )


def _check_dag(
    plan: WorkflowPlan, limits: PlatformLimits, known_ids: set[str]
) -> list[FeasibilityFinding]:
    findings: list[FeasibilityFinding] = []
    edges: dict[str, list[str]] = {}
    for step in plan.steps:
        deps = step.depends_on
        if len(deps) > limits.max_depends_on_per_step:
            findings.append(
                FeasibilityFinding(
                    code=FeasibilityCode.TOO_MANY_DEPENDENCIES,
                    severity=Severity.REJECT,
                    message=f"step '{step.id}' has too many dependencies",
                    step_id=step.id,
                )
            )
        clean_deps: list[str] = []
        for dep in deps:
            if dep == step.id:
                findings.append(
                    FeasibilityFinding(
                        code=FeasibilityCode.SELF_DEPENDENCY,
                        severity=Severity.REJECT,
                        message=f"step '{step.id}' depends on itself",
                        step_id=step.id,
                    )
                )
                continue
            if dep not in known_ids:
                findings.append(
                    FeasibilityFinding(
                        code=FeasibilityCode.UNKNOWN_DEPENDENCY,
                        severity=Severity.REJECT,
                        message=f"step '{step.id}' depends on unknown step '{dep}'",
                        step_id=step.id,
                    )
                )
                continue
            clean_deps.append(dep)
        edges[step.id] = clean_deps

    # Kahn's algorithm over the cleaned edges (dep -> step). A remaining node
    # means a cycle. Only run when references are otherwise sound.
    if not any(f.severity == Severity.REJECT for f in findings):
        indegree = {sid: len(edges[sid]) for sid in edges}
        queue = [sid for sid, d in indegree.items() if d == 0]
        seen = 0
        while queue:
            node = queue.pop()
            seen += 1
            for other, deps in edges.items():
                if node in deps:
                    indegree[other] -= 1
                    if indegree[other] == 0:
                        queue.append(other)
        if seen != len(edges):
            findings.append(
                FeasibilityFinding(
                    code=FeasibilityCode.CYCLE_DETECTED,
                    severity=Severity.REJECT,
                    message="workflow graph contains a cycle",
                )
            )
    return findings


def check_plan(
    plan: WorkflowPlan,
    view: CapabilityView,
    limits: PlatformLimits,
    all_tool_names: set[str],
    *,
    clarification_requested: bool = False,
    clarification_questions: list[str] | None = None,
) -> FeasibilityReport:
    """Deterministically decide the plan's status. Never raises on a bad plan."""
    findings: list[FeasibilityFinding] = []
    approvals: list[str] = []
    questions = list(clarification_questions or [])

    # --- Structural ---
    if len(plan.steps) == 0:
        if clarification_requested:
            findings.append(
                FeasibilityFinding(
                    code=FeasibilityCode.CLARIFICATION_REQUIRED,
                    severity=Severity.CLARIFY,
                    message="planner requested clarification and proposed no steps",
                )
            )
            return FeasibilityReport(
                status=FeasibilityStatus.NEEDS_CLARIFICATION,
                findings=findings,
                clarification_questions=questions,
            )
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.EMPTY_PLAN,
                severity=Severity.REJECT,
                message="plan has no steps",
            )
        )
        return FeasibilityReport(status=FeasibilityStatus.REJECT, findings=findings)

    if len(plan.steps) > limits.max_steps:
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.TOO_MANY_STEPS,
                severity=Severity.REJECT,
                message=f"plan has {len(plan.steps)} steps; limit is {limits.max_steps}",
            )
        )

    # Serialized-size bounds (M12B-A): never let an unbounded arg blob reach
    # durable state. Per-step args first (so the finding names the offender),
    # then the whole plan. compact separators = the persisted-ish size.
    for step in plan.steps:
        args_bytes = len(json.dumps(step.args, default=str, separators=(",", ":")).encode())
        if args_bytes > limits.max_step_args_bytes:
            findings.append(
                FeasibilityFinding(
                    code=FeasibilityCode.ARGS_TOO_LARGE,
                    severity=Severity.REJECT,
                    message=f"step '{step.id}' args exceed {limits.max_step_args_bytes} bytes",
                    step_id=step.id,
                    detail={"bytes": args_bytes, "limit": limits.max_step_args_bytes},
                )
            )
    plan_bytes = len(plan.model_dump_json().encode())
    if plan_bytes > limits.max_plan_bytes:
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.PLAN_TOO_LARGE,
                severity=Severity.REJECT,
                message=f"plan serializes to {plan_bytes} bytes; limit is {limits.max_plan_bytes}",
                detail={"bytes": plan_bytes, "limit": limits.max_plan_bytes},
            )
        )

    ids = [s.id for s in plan.steps]
    duplicates = {i for i in ids if ids.count(i) > 1}
    for dup in sorted(duplicates):
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.DUPLICATE_STEP_ID,
                severity=Severity.REJECT,
                message=f"duplicate step id '{dup}'",
                step_id=dup,
            )
        )
    known_ids = set(ids)

    # --- Per-step: tool, connector, args, SQL ---
    total_timeout = 0
    normalized_steps: list[WorkflowStep] = []
    for step in plan.steps:
        tool = view.tool(step.tool)
        if tool is None:
            code = (
                FeasibilityCode.TOOL_NOT_AVAILABLE
                if step.tool in all_tool_names
                else FeasibilityCode.UNKNOWN_TOOL
            )
            findings.append(
                FeasibilityFinding(
                    code=code,
                    severity=Severity.REJECT,
                    message=f"tool '{step.tool}' is not available to this tenant",
                    step_id=step.id,
                )
            )
            normalized_steps.append(step)
            continue

        total_timeout += tool.timeout_seconds
        if tool.timeout_seconds > limits.max_step_timeout_seconds:
            findings.append(
                FeasibilityFinding(
                    code=FeasibilityCode.STEP_TIMEOUT_EXCEEDED,
                    severity=Severity.REJECT,
                    message=f"tool '{tool.name}' timeout exceeds platform limit",
                    step_id=step.id,
                )
            )
        if tool.requires_approval:
            approvals.append(step.id)
            findings.append(
                FeasibilityFinding(
                    code=FeasibilityCode.APPROVAL_REQUIRED,
                    severity=Severity.APPROVE,
                    message=f"tool '{tool.name}' requires approval",
                    step_id=step.id,
                )
            )

        connector, conn_findings = _validate_connector(step, tool, view)
        findings.extend(conn_findings)

        args_ok, arg_finding = _validate_args(step, tool)
        if arg_finding is not None:
            findings.append(arg_finding)

        normalized_step = step
        if args_ok and step.tool == _POSTGRES_QUERY_TOOL and connector is not None:
            rendered, sql_finding = _validate_sql(step, connector)
            if sql_finding is not None:
                findings.append(sql_finding)
            elif rendered is not None:
                normalized_step = step.model_copy(update={"args": {**step.args, "sql": rendered}})
        normalized_steps.append(normalized_step)

    if total_timeout > limits.max_total_timeout_seconds:
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.TOTAL_TIMEOUT_EXCEEDED,
                severity=Severity.REJECT,
                message="total workflow timeout exceeds platform limit",
            )
        )

    # --- DAG ---
    findings.extend(_check_dag(plan, limits, known_ids))

    # --- Clarification (advisory request from the model, on a non-empty plan) ---
    if clarification_requested:
        findings.append(
            FeasibilityFinding(
                code=FeasibilityCode.CLARIFICATION_REQUIRED,
                severity=Severity.CLARIFY,
                message="planner requested clarification",
            )
        )

    status = _decide_status(findings, approvals)
    normalized_plan = (
        WorkflowPlan(steps=normalized_steps) if status != FeasibilityStatus.REJECT else None
    )
    return FeasibilityReport(
        status=status,
        findings=findings,
        approvals_required=approvals,
        clarification_questions=questions,
        normalized_plan=normalized_plan,
    )
