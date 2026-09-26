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

export type MemberRole = "owner" | "admin" | "member";

export interface MemberOut {
  user_id: string;
  role: MemberRole;
}

export interface InvitationOut {
  id: string;
  email: string;
  role: "admin" | "member";
  status: string;
  expires_at: string;
  created_at: string;
}

// The POST /invitations response ALSO carries the raw token, returned exactly
// once. It is displayed for manual copying and never persisted (no localStorage,
// no logging).
export interface InvitationCreatedOut extends InvitationOut {
  token: string;
}

export interface InvitationAcceptedOut {
  workspace_id: string;
  role: MemberRole;
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
  // The user who requested the approved action (null when it cannot be
  // resolved). Surfaced so a decider knows who is asking.
  requested_by_user_id: string | null;
  // Whether the current viewer is allowed to decide THIS approval. The backend
  // is authoritative; the UI uses this only to enable/disable controls (e.g. a
  // requester cannot approve their own action).
  viewer_can_decide: boolean;
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
  // Fail-closed authorization block (migration 0020): set by the scheduler when the
  // creator lost membership/role. A blocked schedule creates NO occurrences even
  // while enabled=true, so status precedence is blocked > active > disabled.
  blocked_reason: string | null;
  blocked_at: string | null;
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

// Request→plan provenance (M12B-A): what caused a workflow version to exist.
export interface WorkflowProvenanceOut {
  workflow_version_id: string;
  request_text: string | null;
  request_sha256: string | null;
  provider: string;
  model: string;
  planner_contract_version: string | null;
  status: string;
  created_at: string;
}

// Deterministic grounded run summary (M12B-A). No model output; step outcomes
// are keyed to step ids and UNKNOWN/FAILED/SKIPPED are never reported as success.
export interface StepSummaryOut {
  step_id: string;
  tool: string;
  outcome: string;
  detail: string;
}

export interface RunSummaryOut {
  run_status: string;
  outcome: string;
  headline: string;
  steps: StepSummaryOut[];
  total_steps: number;
  succeeded: number;
  failed: number;
  unknown: number;
  skipped: number;
  truncated: boolean;
}

// A plan step as stored in a normalized workflow plan.
export interface PlanStep {
  id: string;
  tool: string;
  connector?: string | null;
  args?: Record<string, unknown>;
  depends_on?: string[];
}
