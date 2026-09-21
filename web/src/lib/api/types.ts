// TypeScript mirrors of the backend response models (nlw.api.schemas).

export interface UserOut {
  id: string;
  email: string;
}

export interface WorkspaceOut {
  id: string;
  name: string;
  slug: string;
  role: "owner" | "admin" | "member" | string;
}

export interface TenantContextOut {
  tenant_id: string;
  role: string;
}

export interface ConnectorOut {
  id: string;
  type: string;
  name: string;
  config: Record<string, unknown>;
  status: string;
  has_secret: boolean;
}

export interface ToolOut {
  name: string;
  description: string;
  category: string;
  connector_type: string | null;
  read_only: boolean;
  requires_approval: boolean;
  timeout_seconds: number;
}

export type FeasibilityStatus = "PASS" | "REJECT" | "NEEDS_CLARIFICATION" | "NEEDS_APPROVAL";

export interface PlanProposalOut {
  id: string;
  status: FeasibilityStatus;
  workflow_name: string;
  provider: string;
  model: string;
  proposed_plan: Record<string, unknown> | null;
  normalized_plan: Record<string, unknown> | null;
  feasibility: Record<string, unknown>;
  clarification_questions: string[] | null;
  workflow_version_id: string | null;
}

export interface MaterializeOut {
  workflow_id: string;
  workflow_version_id: string;
  idempotent_hit: boolean;
}

export interface ApprovalOut {
  id: string;
  run_id: string;
  step_id: string;
  tool: string;
  connector_name: string;
  status: string;
  requested_at: string | null;
  decided_at: string | null;
  // The effective, non-secret destination the side effect will reach (webhook
  // host / Slack channel), derived from the approved connector. null when it
  // cannot be safely resolved.
  destination: string | null;
  // True when the payload exceeds the safe review size and is therefore NOT
  // shown; the action must not be approved in that state.
  payload_review_blocked: boolean;
  preview: Record<string, unknown>;
}

export interface ApprovalDecisionOut {
  id: string;
  status: string;
  resumed: boolean;
}

export interface ScheduleOut {
  id: string;
  workflow_id: string;
  workflow_version_id: string;
  timezone: string;
  frequency: string;
  minute: number;
  hour: number | null;
  day_of_week: number | null;
  enabled: boolean;
  next_run_at: string;
  last_scheduled_for: string | null;
}

export interface WorkflowOut {
  id: string;
  name: string;
  current_version_id: string | null;
  created_at: string;
}

export interface WorkflowVersionOut {
  id: string;
  workflow_id: string;
  version: number;
  plan: Record<string, unknown>;
}

export interface WorkflowDetailOut extends WorkflowOut {
  current_version: WorkflowVersionOut | null;
}

export interface RunOut {
  id: string;
  workflow_id: string;
  workflow_version_id: string;
  status: string;
  trigger: string;
  schedule_id: string | null;
  scheduled_for: string | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface StepRunOut {
  step_id: string;
  tool: string;
  status: string;
  attempt: number;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  output_preview: Record<string, unknown> | null;
  output_truncated: boolean;
}

export interface ExternalActionOut {
  step_id: string;
  tool: string;
  destination_summary: string | null;
  status: string;
  attempts: number;
  error_class: string | null;
  http_status: number | null;
  last_attempt_at: string | null;
  next_attempt_at: string | null;
}

export interface RunCreateOut {
  run_id: string;
  status: string;
  idempotent_hit: boolean;
}

// A plan step as stored in a normalized workflow plan.
export interface PlanStep {
  id: string;
  tool: string;
  connector?: string | null;
  args?: Record<string, unknown>;
  depends_on?: string[];
}
