// The BFF is NOT a generic tunnel. Only the exact (method, path) pairs the M10
// UI needs are allowed; everything else is rejected (M10 change #3).

interface Rule {
  method: string;
  pattern: RegExp;
}

const UUID = "[0-9a-fA-F-]{36}";

const RULES: Rule[] = [
  // Identity / workspaces
  { method: "GET", pattern: /^\/me$/ },
  { method: "GET", pattern: /^\/workspaces$/ },
  { method: "POST", pattern: /^\/workspaces$/ },
  { method: "GET", pattern: /^\/workspaces\/current$/ },
  // Connectors / tools
  { method: "GET", pattern: /^\/connectors$/ },
  { method: "POST", pattern: /^\/connectors$/ },
  { method: "GET", pattern: /^\/tools$/ },
  // Plans
  { method: "GET", pattern: /^\/plans$/ },
  { method: "GET", pattern: new RegExp(`^/plans/${UUID}$`) },
  { method: "POST", pattern: /^\/plans$/ },
  { method: "POST", pattern: new RegExp(`^/plans/${UUID}/materialize$`) },
  // Workflows
  { method: "GET", pattern: /^\/workflows$/ },
  { method: "GET", pattern: new RegExp(`^/workflows/${UUID}$`) },
  { method: "GET", pattern: new RegExp(`^/workflow-versions/${UUID}$`) },
  // Consumed by useWorkflowProvenance (workflow detail "Original request" card).
  { method: "GET", pattern: new RegExp(`^/workflow-versions/${UUID}/provenance$`) },
  { method: "POST", pattern: new RegExp(`^/workflows/${UUID}/runs$`) },
  // Runs
  { method: "GET", pattern: /^\/runs$/ },
  { method: "GET", pattern: new RegExp(`^/runs/${UUID}$`) },
  { method: "GET", pattern: new RegExp(`^/runs/${UUID}/steps$`) },
  { method: "GET", pattern: new RegExp(`^/runs/${UUID}/actions$`) },
  // Consumed by useRunSummary (run detail result-summary card).
  { method: "GET", pattern: new RegExp(`^/runs/${UUID}/summary$`) },
  // Approvals
  { method: "GET", pattern: /^\/approvals$/ },
  { method: "POST", pattern: new RegExp(`^/approvals/${UUID}/approve$`) },
  { method: "POST", pattern: new RegExp(`^/approvals/${UUID}/reject$`) },
  // Schedules
  { method: "GET", pattern: /^\/schedules$/ },
  { method: "GET", pattern: new RegExp(`^/schedules/${UUID}$`) },
  { method: "POST", pattern: /^\/schedules$/ },
  { method: "PATCH", pattern: new RegExp(`^/schedules/${UUID}$`) },
  { method: "DELETE", pattern: new RegExp(`^/schedules/${UUID}$`) },
  // Members / invitations (M11.5 P3A)
  { method: "GET", pattern: /^\/members$/ },
  { method: "PATCH", pattern: new RegExp(`^/members/${UUID}$`) },
  { method: "DELETE", pattern: new RegExp(`^/members/${UUID}$`) },
  { method: "GET", pattern: /^\/invitations$/ },
  { method: "POST", pattern: /^\/invitations$/ },
  { method: "POST", pattern: new RegExp(`^/invitations/${UUID}/revoke$`) },
  { method: "POST", pattern: /^\/invitations\/accept$/ },
];

/** True only when the exact method+path is explicitly allowed. */
export function isAllowed(method: string, path: string): boolean {
  return RULES.some((r) => r.method === method.toUpperCase() && r.pattern.test(path));
}
