import { cookies } from "next/headers";
import { createHmac, timingSafeEqual } from "crypto";

// The selected workspace id is kept in a server-signed cookie. Signing prevents
// client tampering of the UX selection; backend RLS/membership remains the
// authoritative access control regardless of this value (M10 change #5).

const COOKIE_NAME = "nlw_ws";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function secret(): string {
  return process.env.WORKSPACE_COOKIE_SECRET || "dev-insecure-workspace-cookie-secret-change-me";
}

function sign(value: string): string {
  return createHmac("sha256", secret()).update(value).digest("hex");
}

function verify(value: string, sig: string): boolean {
  const expected = sign(value);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Read + verify the selected workspace id from the signed cookie. */
export async function getSelectedWorkspace(): Promise<string | null> {
  const store = await cookies();
  const raw = store.get(COOKIE_NAME)?.value;
  if (!raw) return null;
  const [id, sig] = raw.split(".");
  if (!id || !sig || !UUID_RE.test(id) || !verify(id, sig)) return null;
  return id;
}

/** Serialize the signed cookie value for a workspace id. */
export function serializeWorkspaceCookie(workspaceId: string): {
  name: string;
  value: string;
} {
  return { name: COOKIE_NAME, value: `${workspaceId}.${sign(workspaceId)}` };
}

export const WORKSPACE_COOKIE_NAME = COOKIE_NAME;
export const isUuid = (v: string): boolean => UUID_RE.test(v);
