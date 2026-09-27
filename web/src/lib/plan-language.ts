/**
 * User language for plans, runs and their checks. Presentation only: statuses,
 * tool names and feasibility codes come from the backend unchanged; this maps
 * them to words a pilot user understands. Unknown values fall back to a
 * neutral phrase — never to raw backend text.
 */

const STATUS_LABEL: Record<string, string> = {
  PASS: "Ready",
  NEEDS_APPROVAL: "Needs approval",
  NEEDS_CLARIFICATION: "Needs detail",
  REJECT: "Blocked",
  COMPLETED: "Completed",
  SUCCESS: "Succeeded",
  FAILED: "Failed",
  PARTIAL: "Partial",
  RUNNING: "Running",
  IN_PROGRESS: "In progress",
  PENDING: "Queued",
  WAITING_APPROVAL: "Awaiting approval",
  SKIPPED: "Skipped",
  UNKNOWN: "Outcome unknown",
  unknown: "Outcome unknown",
  FAILED_WITH_UNKNOWN: "Outcome unknown",
  ACTION_OUTCOME_UNKNOWN: "Outcome unknown",
  OUTCOME_UNAVAILABLE: "Outcome unconfirmed",
  OUTCOME_PENDING: "Checking outcome",
  active: "Active",
  approved: "Approved",
  rejected: "Rejected",
  pending: "Pending",
  error: "Error",
  unchecked: "Not yet checked",
  disabled: "Disabled",
  blocked: "Blocked",
};

export function statusLabel(status: string | null | undefined): string {
  if (!status) return "Unknown";
  if (status in STATUS_LABEL) return STATUS_LABEL[status];
  const words = status.replace(/_/g, " ").toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

const TOOL_LABEL: Record<string, string> = {
  "pilot.sales_analysis": "Analyze synthetic sales data",
  "pilot.support_analysis": "Analyze synthetic support tickets",
  "slack.send_message": "Share to Slack (after approval)",
  "postgres.query": "Read from a database (read-only)",
  "webhook.send": "Send to a webhook (after approval)",
  "fake.echo": "Test step",
  "fake.fail": "Test step (fails on purpose)",
  "static.echo": "Test step",
  "static.secret_check": "Check the connector's credential",
};

export function toolLabel(tool: unknown): string {
  const t = typeof tool === "string" ? tool : "";
  return TOOL_LABEL[t] ?? "Registered tool";
}

/** What the plan's check result means and what to do next. */
export const PLAN_STATUS_COPY: Record<string, string> = {
  PASS: "All checks passed. Save it as a workflow, then run it.",
  NEEDS_APPROVAL:
    "All checks passed. It includes an action that leaves NLW, so a second person must approve that step before it runs.",
  NEEDS_CLARIFICATION:
    "The planner needs a little more detail. Answer the questions below in your request and prepare the plan again.",
  REJECT:
    "This plan can't be used: it asks for something the pilot doesn't allow. Rephrase your question — for example, pick one of the sample datasets — and prepare the plan again.",
};

export function planStatusCopy(status: string): string {
  return (
    PLAN_STATUS_COPY[status] ?? "This plan can't be used yet. Revise your request and try again."
  );
}

const FINDING_COPY: Record<string, string> = {
  UNKNOWN_TOOL: "A step asks for a capability NLW doesn't have.",
  TOOL_NOT_AVAILABLE: "A step uses a capability that isn't enabled in this workspace.",
  CONNECTOR_REQUIRED: "A step needs a connector, but none was chosen.",
  CONNECTOR_NOT_FOUND: "A step refers to a connector this workspace doesn't have.",
  CONNECTOR_TYPE_MISMATCH: "A step uses a connector of the wrong kind.",
  CONNECTOR_UNUSABLE: "A connector this plan needs is disabled or not ready.",
  CONNECTOR_HEALTH_UNVERIFIED: "A connector this plan needs hasn't been checked yet.",
  CONNECTOR_CONFIG_CHANGED: "A connector changed after this plan was prepared.",
  CONNECTOR_ON_CONNECTORLESS_TOOL: "A step names a connector it doesn't use.",
  ARG_VALIDATION_FAILED: "A step's settings aren't valid.",
  ARGS_TOO_LARGE: "A step's settings are too large.",
  SQL_REJECTED: "A database query isn't allowed (only safe, read-only queries are).",
  POLICY_DENIED: "A step isn't allowed by this workspace's policy.",
  APPROVAL_REQUIRED: "A step sends something outside NLW and will wait for approval.",
  CLARIFICATION_REQUIRED: "The request is ambiguous.",
  EMPTY_PLAN: "The planner didn't propose any steps.",
  PLAN_TOO_LARGE: "The plan has too many steps.",
  TOO_MANY_STEPS: "The plan has too many steps.",
  TOO_MANY_DEPENDENCIES: "The plan's steps are too interconnected.",
  CYCLE_DETECTED: "The plan's steps depend on each other in a loop.",
  SELF_DEPENDENCY: "A step depends on itself.",
  UNKNOWN_DEPENDENCY: "A step depends on a step that doesn't exist.",
  DUPLICATE_STEP_ID: "Two steps have the same name.",
  STEP_TIMEOUT_EXCEEDED: "A step would take longer than allowed.",
  TOTAL_TIMEOUT_EXCEEDED: "The plan would take longer than allowed.",
  PLANNER_INVALID_OUTPUT: "The planner's answer couldn't be used.",
  INVALID_PLAN: "The plan isn't valid.",
  STALE_PLAN: "Something changed after this plan was prepared.",
};

export function findingText(code: unknown): string {
  const c = typeof code === "string" ? code : "";
  return FINDING_COPY[c] ?? "A safety check flagged this plan.";
}
