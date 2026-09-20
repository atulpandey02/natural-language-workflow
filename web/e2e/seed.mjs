// Seed the E2E stack: two Supabase users (admin + member), two workspaces owned
// by the admin, and a member-role membership in the first workspace. Emits the
// E2E_* credentials to stdout (the workflow appends them to $GITHUB_ENV).
//
// Dependency-free: uses GoTrue REST + the compose Postgres via `psql`.

import { execSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const SUPABASE = process.env.SUPABASE_API_URL;
const SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANON = process.env.SUPABASE_ANON_KEY;
const API = process.env.NLW_API_BASE ?? "http://localhost:8000";

const ADMIN = { email: "e2e-admin@example.com", password: "E2e-admin-pass-123!" };
const MEMBER = { email: "e2e-member@example.com", password: "E2e-member-pass-123!" };

async function createUser(user) {
  const res = await fetch(`${SUPABASE}/auth/v1/admin/users`, {
    method: "POST",
    headers: {
      apikey: SERVICE_ROLE,
      Authorization: `Bearer ${SERVICE_ROLE}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ ...user, email_confirm: true }),
  });
  if (!res.ok && res.status !== 422) {
    throw new Error(`createUser ${user.email} failed: ${res.status} ${await res.text()}`);
  }
}

async function signIn(user) {
  const res = await fetch(`${SUPABASE}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: ANON, "Content-Type": "application/json" },
    body: JSON.stringify(user),
  });
  if (!res.ok) throw new Error(`signIn ${user.email} failed: ${res.status} ${await res.text()}`);
  return (await res.json()).access_token;
}

async function apiGet(path, token, workspaceId) {
  const headers = { Authorization: `Bearer ${token}` };
  if (workspaceId) headers["X-Workspace-Id"] = workspaceId;
  const res = await fetch(`${API}${path}`, { headers });
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status} ${await res.text()}`);
  return res.json();
}

async function createWorkspace(token, name) {
  const res = await fetch(`${API}/workspaces`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  if (!res.ok) throw new Error(`create workspace failed: ${res.status} ${await res.text()}`);
  return (await res.json()).id;
}

// Decode JWT metadata WITHOUT logging the token/sub/email (M10 E2E diagnostic).
function jwtMeta(token) {
  const [h, p] = token.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  return { alg: header.alg, kidPresent: Boolean(header.kid), iss: payload.iss, aud: payload.aud };
}

function psql(sql) {
  const cmd = `docker compose exec -T postgres psql -U nlw -d nlw -tAc ${JSON.stringify(sql)}`;
  return execSync(cmd, { encoding: "utf8" }).trim();
}

async function main() {
  await createUser(ADMIN);
  await createUser(MEMBER);

  const adminToken = await signIn(ADMIN);

  // Evidence-first: log ONLY token metadata (never the token/sub/email) to stderr
  // so it does not pollute $GITHUB_ENV. Confirms which verification path the API
  // must use for the seeded user's access token.
  const meta = jwtMeta(adminToken);
  console.error(
    `[seed] admin token metadata: alg=${meta.alg} kid_present=${meta.kidPresent} ` +
      `iss=${meta.iss} aud=${JSON.stringify(meta.aud)}`,
  );
  if (meta.alg === "HS256") {
    console.error(
      "[seed] token is HS256 — expected asymmetric (ES256/RS256) for local Supabase. " +
        "The JWKS root cause does not apply; investigate the CLI signing mode. Stopping.",
    );
    process.exit(3);
  }

  await apiGet("/me", adminToken); // provision the admin app-user row
  const ws1 = await createWorkspace(adminToken, "E2E Primary");
  await createWorkspace(adminToken, "E2E Secondary"); // 2nd workspace for the switch test

  // Seed a materialized fake.echo workflow in the primary workspace so the UI has
  // a runnable target for Run-now / observe / double-click. The CI planner is the
  // keyless stub (always NEEDS_CLARIFICATION), so a materializable workflow cannot
  // be produced through the planner in CI — seed one directly as the DB owner.
  const wf = randomUUID();
  const ver = randomUUID();
  const plan = JSON.stringify({ steps: [{ id: "a", tool: "fake.echo", args: {} }] });
  psql(
    `INSERT INTO workflows (id, tenant_id, name) VALUES ('${wf}','${ws1}','E2E Seeded Workflow')`,
  );
  psql(
    `INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) ` +
      `VALUES ('${ver}','${ws1}','${wf}',1,'${plan}'::jsonb)`,
  );
  psql(`UPDATE workflows SET current_version_id='${ver}' WHERE id='${wf}'`);

  const memberToken = await signIn(MEMBER);
  await apiGet("/me", memberToken); // provision the member app-user row

  // Add the member (role=member) to the primary workspace. No invite API exists
  // (deferred), so seed the membership directly as the DB owner.
  psql(
    `INSERT INTO memberships (id, user_id, workspace_id, role) ` +
      `SELECT gen_random_uuid(), u.id, '${ws1}', 'member' FROM users u ` +
      `WHERE u.email = '${MEMBER.email}' ` +
      `ON CONFLICT DO NOTHING`,
  );

  // Emit credentials for the Playwright job.
  process.stdout.write(
    [
      `E2E_ADMIN_EMAIL=${ADMIN.email}`,
      `E2E_ADMIN_PASSWORD=${ADMIN.password}`,
      `E2E_MEMBER_EMAIL=${MEMBER.email}`,
      `E2E_MEMBER_PASSWORD=${MEMBER.password}`,
      "",
    ].join("\n"),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
