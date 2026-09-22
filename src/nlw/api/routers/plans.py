"""Planner endpoints (M6).

- ``POST /plans``                 propose a plan (LLM) + deterministic feasibility
- ``GET  /plans``                 list the tenant's proposals (audit)
- ``GET  /plans/{id}``            read one proposal
- ``POST /plans/{id}/materialize`` PASS-only, revalidated, idempotent -> workflow_version

Planning runs API-side. The LLM sees only the tenant capability view (Tool
Registry + secret-free connectors); it never receives secrets or the LLM key.
The raw prompt and raw provider response are never stored. Deterministic
feasibility owns the final status — a parsed plan is not executable.
"""

import hashlib
import time
import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

import nlw.tools.builtin  # noqa: F401  (populates the tool + connector-type registries)
from nlw.api.capability import build_tenant_view
from nlw.api.deps import (
    get_app_settings,
    get_llm_provider,
    get_session,
    get_tenant_context,
    rate_limit,
)
from nlw.api.schemas import (
    MaterializeOut,
    PlanProposalDetailOut,
    PlanProposalOut,
    PlanRequest,
)
from nlw.core.config import Settings
from nlw.db.models import Workflow, WorkflowVersion
from nlw.db.quota import QuotaExceededError, enforce_cap, workflows_count_stmt
from nlw.db.repositories import PlanProposalRepository
from nlw.domain.workflow import WorkflowPlan
from nlw.feasibility.engine import FeasibilityReport
from nlw.feasibility.limits import DEFAULT_LIMITS
from nlw.feasibility.revalidation import revalidate_plan
from nlw.observability import metrics
from nlw.planner.budget import PromptBudgetError
from nlw.planner.planner import plan_and_check
from nlw.planner.provider import (
    LLMAuthError,
    LLMProvider,
    LLMTimeoutError,
    LLMUnavailableError,
)
from nlw.planner.schema import PLANNER_CONTRACT_VERSION
from nlw.tenancy.context import TenantContext

router = APIRouter()
log = structlog.get_logger(__name__)


def _feasibility_dict(report: FeasibilityReport) -> dict[str, object]:
    # Persist the report WITHOUT normalized_plan (stored in its own column).
    return report.model_dump(mode="json", exclude={"normalized_plan"})


@router.post(
    "/plans",
    response_model=PlanProposalDetailOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("plans", "plans"))],
)
async def create_plan(
    body: PlanRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
    provider: LLMProvider = Depends(get_llm_provider),
    settings: Settings = Depends(get_app_settings),
) -> PlanProposalDetailOut:
    prompt = body.prompt
    if len(prompt) > settings.llm_max_prompt_chars:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"prompt exceeds maximum length of {settings.llm_max_prompt_chars} characters",
        )
    if not prompt.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "prompt must not be empty")

    view, all_tool_names = await build_tenant_view(session, ctx.tenant_id)

    planner_start = time.perf_counter()
    try:
        result = await plan_and_check(
            provider=provider,
            view=view,
            all_tool_names=all_tool_names,
            limits=DEFAULT_LIMITS,
            user_request=prompt,
            max_output_tokens=settings.llm_max_output_tokens,
            timeout_s=settings.llm_timeout_s,
        )
    except (LLMTimeoutError, LLMUnavailableError) as exc:
        # Infrastructure fault — NOT a feasibility REJECT; no proposal row.
        metrics.record_error("planner_unavailable")
        log.warning(
            "planner.provider_error", error_class="unavailable", provider=settings.llm_provider
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "planner provider unavailable"
        ) from exc
    except LLMAuthError as exc:
        metrics.record_error("planner_auth")
        log.error("planner.provider_error", error_class="auth", provider=settings.llm_provider)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "planner provider misconfigured") from exc
    except PromptBudgetError as exc:
        # Deterministic: the assembled prompt/tool catalog exceeded its budget.
        # Rejected before any provider call; never truncated (Part G).
        metrics.record_error("planner_prompt_budget")
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    finally:
        metrics.observe_planner(time.perf_counter() - planner_start)

    report = result.report
    metrics.record_plan(report.status.value)
    # AI-core observability (M12B-A, Part I): token usage, invalid-output rate,
    # reject reasons by stable code, and the proposed-plan shape. All bounded.
    metrics.observe_planner_tokens(result.input_tokens, result.output_tokens)
    if result.output is None:
        metrics.record_planner_invalid_output()
    else:
        plan_obj = result.output.to_workflow_plan()
        metrics.observe_plan_shape(
            len(result.output.steps), len(plan_obj.model_dump_json().encode())
        )
    for finding in report.findings:
        if finding.severity == "reject":
            metrics.record_feasibility_reject(finding.code.value)
    proposed_plan = result.output.to_workflow_plan().model_dump() if result.output else None
    normalized_plan = (
        report.normalized_plan.model_dump() if report.normalized_plan is not None else None
    )

    proposal = await PlanProposalRepository(session).create(
        tenant_id=ctx.tenant_id,
        created_by=ctx.user_id,
        prompt_len=len(prompt),
        provider=settings.llm_provider,
        model=result.model,
        workflow_name=result.workflow_name,
        status=report.status.value,
        proposed_plan=proposed_plan,
        normalized_plan=normalized_plan,
        feasibility=_feasibility_dict(report),
        clarification_questions=report.clarification_questions,
        request_text=prompt,
        request_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        planner_contract_version=PLANNER_CONTRACT_VERSION,
    )

    # Observability: metadata only. Never the raw prompt (not even at DEBUG).
    log.info(
        "planner.request",
        tenant_id=str(ctx.tenant_id),
        proposal_id=str(proposal.id),
        provider=settings.llm_provider,
        model=result.model,
        prompt_len=len(prompt),
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        step_count=len(result.output.steps) if result.output else 0,
    )
    log.info(
        "feasibility.check",
        tenant_id=str(ctx.tenant_id),
        proposal_id=str(proposal.id),
        status=report.status.value,
        failure_codes=[f.code.value for f in report.findings if f.severity == "reject"],
        approvals_required=report.approvals_required,
        clarification_count=len(report.clarification_questions),
    )
    return PlanProposalDetailOut.model_validate(proposal)


@router.get("/plans", response_model=list[PlanProposalOut])
async def list_plans(
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> list[PlanProposalOut]:
    proposals = await PlanProposalRepository(session).list_for_tenant(ctx.tenant_id)
    return [PlanProposalOut.model_validate(p) for p in proposals]


@router.get("/plans/{proposal_id}", response_model=PlanProposalDetailOut)
async def get_plan(
    proposal_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> PlanProposalDetailOut:
    proposal = await PlanProposalRepository(session).get(proposal_id, ctx.tenant_id)
    if proposal is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "proposal not found")
    return PlanProposalDetailOut.model_validate(proposal)


@router.post(
    "/plans/{proposal_id}/materialize",
    response_model=MaterializeOut,
    dependencies=[Depends(rate_limit("materialize", "write"))],
)
async def materialize_plan(
    proposal_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_app_settings),
) -> MaterializeOut:
    repo = PlanProposalRepository(session)
    proposal = await repo.get_for_update(proposal_id, ctx.tenant_id)
    if proposal is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "proposal not found")

    # Idempotent: already materialized -> return the existing version, no re-create.
    if proposal.workflow_version_id is not None:
        version = await session.get(WorkflowVersion, proposal.workflow_version_id)
        assert version is not None
        return MaterializeOut(
            workflow_id=version.workflow_id,
            workflow_version_id=version.id,
            idempotent_hit=True,
        )

    if proposal.proposed_plan is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "proposal has no materializable plan")
    # Only a previously-ACCEPTED proposal can materialize; a REJECT/CLARIFY
    # proposal was never executable (INVALID/POLICY at creation), never STALE.
    if proposal.status not in ("PASS", "NEEDS_APPROVAL"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "INVALID_PLAN", "message": "This proposal was not accepted."},
        )

    # Never trust the stored PASS: re-validate against CURRENT tenant capabilities
    # and classify a no-longer-executable plan (STALE_PLAN / POLICY_DENIED /
    # INVALID_PLAN) with a stable, sanitized reason.
    plan = WorkflowPlan.model_validate(proposal.proposed_plan)
    view, all_tool_names = await build_tenant_view(session, ctx.tenant_id)
    reval = revalidate_plan(plan, view, DEFAULT_LIMITS, all_tool_names)

    if not reval.fresh or reval.report.normalized_plan is None:
        metrics.record_stale_plan(reval.outcome.value, reval.reason_code)
        log.info(
            "plan.materialize",
            tenant_id=str(ctx.tenant_id),
            proposal_id=str(proposal.id),
            revalidation_outcome=reval.outcome.value,
            reason_code=reval.reason_code,
            idempotent_hit=False,
        )
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": reval.outcome.value, "message": reval.message},
        )
    report = reval.report
    assert report.normalized_plan is not None  # fresh guarantees a normalized plan

    # Concurrency-safe per-tenant workflow cap (a materialized workflow is a
    # durable resource); the advisory lock serializes concurrent materializes.
    try:
        await enforce_cap(
            session,
            resource="workflows",
            tenant_id=ctx.tenant_id,
            cap=settings.max_workflows_per_tenant,
            count_stmt=workflows_count_stmt(ctx.tenant_id),
        )
    except QuotaExceededError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    workflow = Workflow(tenant_id=ctx.tenant_id, name=proposal.workflow_name)
    session.add(workflow)
    await session.flush()
    version = WorkflowVersion(
        tenant_id=ctx.tenant_id,
        workflow_id=workflow.id,
        version=1,
        plan=report.normalized_plan.model_dump(),
    )
    session.add(version)
    await session.flush()
    workflow.current_version_id = version.id
    proposal.workflow_version_id = version.id
    await session.flush()

    log.info(
        "plan.materialize",
        tenant_id=str(ctx.tenant_id),
        proposal_id=str(proposal.id),
        revalidation_status="PASS",
        workflow_version_id=str(version.id),
        idempotent_hit=False,
    )
    return MaterializeOut(
        workflow_id=workflow.id,
        workflow_version_id=version.id,
        idempotent_hit=False,
    )
