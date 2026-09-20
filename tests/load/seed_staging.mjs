// M11 staging/load seed. Runs AFTER web/e2e/seed.mjs (which creates the users,
// two admin workspaces, a member membership, and a materialized workflow).
//
// Emits into $GITHUB_ENV (never to the log):
//   K6_ADMIN_TOKEN        - admin access token (MASKED via ::add-mask::)
//   K6_WORKSPACE          - admin primary workspace (tenant A)
//   TENANT_A_WORKSPACE    - tenant A (has the seeded workflow)
//   TENANT_B_WORKSPACE    - tenant B (admin's second workspace)
//   TENANT_A_WORKFLOW_ID  - a resource id owned by A (for cross-tenant asserts)
//
// Dependency-free (GoTrue REST + the NLW API). No production/customer data.

import { appendFileSync } from "node:fs";

const SUPABASE = process.env.SUPABASE_API_URL;
const ANON = process.env.SUPABASE_ANON_KEY;
const API = process.env.NLW_API_BASE ?? "http://127.0.0.1:8000";
const GITHUB_ENV = process.env.GITHUB_ENV;

const ADMIN = { email: "e2e-admin@example.com", password: "E2e-admin-pass-123!" };

async function signIn(user) {
  const res = await fetch(`${SUPABASE}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: ANON, "Content-Type": "application/json" },
    body: JSON.stringify(user),
  });
  if (!res.ok) throw new Error(`signIn failed: ${res.status}`);
  return (await res.json()).access_token;
}

async function apiGet(path, token, workspaceId) {
  const headers = { Authorization: `Bearer ${token}` };
  if (workspaceId) headers["X-Workspace-Id"] = workspaceId;
  const res = await fetch(`${API}${path}`, { headers });
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
  return res.json();
}

function emit(lines) {
  if (!GITHUB_ENV) throw new Error("GITHUB_ENV not set");
  appendFileSync(GITHUB_ENV, lines.join("\n") + "\n");
}

async function main() {
  const token = await signIn(ADMIN);
  if (!token) throw new Error("empty admin token");

  // Two distinct tenants owned by admin (created by seed.mjs), ordered by
  // creation → [primary (A), secondary (B)].
  const workspaces = await apiGet("/workspaces", token);
  if (workspaces.length < 2) throw new Error(`expected >=2 workspaces, got ${workspaces.length}`);
  const tenantA = workspaces[0].id;
  const tenantB = workspaces[1].id;

  // A resource owned by tenant A (the seeded workflow) for cross-tenant asserts.
  const aWorkflows = await apiGet("/workflows", token, tenantA);
  const aWorkflowId = aWorkflows.length ? aWorkflows[0].id : "";

  // Mask the token in the runner logs; then write env WITHOUT printing the value.
  process.stdout.write(`::add-mask::${token}\n`);
  emit([
    `K6_ADMIN_TOKEN=${token}`,
    `K6_WORKSPACE=${tenantA}`,
    `TENANT_A_WORKSPACE=${tenantA}`,
    `TENANT_B_WORKSPACE=${tenantB}`,
    `TENANT_A_WORKFLOW_ID=${aWorkflowId}`,
  ]);
  // Safe (non-secret) confirmation to the log.
  console.log(`seed_staging: tenants A=${tenantA} B=${tenantB}; token=<masked, len ${token.length}>`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
