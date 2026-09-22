"""Creation helpers for workflows, immutable versions, and runs.

Sync (worker/engine side). Callers apply a signed context first (RLS INSERT
checks tenant_id = public.ctx_tenant_id()). No HTTP/API surface in M3; used by
tests and, later, by the planner/API.
"""

import uuid

from sqlalchemy.orm import Session

from nlw.db.models import Workflow, WorkflowRun, WorkflowVersion
from nlw.domain.workflow import WorkflowPlan


def create_workflow_with_version(
    session: Session, tenant_id: uuid.UUID, name: str, plan: WorkflowPlan
) -> tuple[Workflow, WorkflowVersion]:
    workflow = Workflow(tenant_id=tenant_id, name=name)
    session.add(workflow)
    session.flush()
    version = WorkflowVersion(
        tenant_id=tenant_id,
        workflow_id=workflow.id,
        version=1,
        plan=plan.model_dump(),
    )
    session.add(version)
    session.flush()
    workflow.current_version_id = version.id
    return workflow, version


def create_run(
    session: Session,
    tenant_id: uuid.UUID,
    workflow_id: uuid.UUID,
    workflow_version_id: uuid.UUID,
    idempotency_key: str | None = None,
) -> WorkflowRun:
    run = WorkflowRun(
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        workflow_version_id=workflow_version_id,
        status="PENDING",
        idempotency_key=idempotency_key,
    )
    session.add(run)
    session.flush()
    return run
