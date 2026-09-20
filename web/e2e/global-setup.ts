import { env, liveStackConfigured, E2E_REQUIRED } from "./helpers";

// In required mode, fail the ENTIRE run up front if the seeded-stack env is
// missing — the suite must never silently pass by skipping (M10 gate).
export default function globalSetup(): void {
  if (!E2E_REQUIRED) return;
  const missing: string[] = [];
  if (!env.baseURL) missing.push("E2E_BASE_URL");
  if (!env.adminEmail || !env.adminPassword) missing.push("E2E_ADMIN_EMAIL/E2E_ADMIN_PASSWORD");
  if (!env.memberEmail || !env.memberPassword) missing.push("E2E_MEMBER_EMAIL/E2E_MEMBER_PASSWORD");
  if (!liveStackConfigured || missing.length > 0) {
    throw new Error(
      `E2E_REQUIRED=1 but the seeded-stack configuration is incomplete: missing ${missing.join(
        ", ",
      )}. Refusing to skip the required E2E suite.`,
    );
  }
}
