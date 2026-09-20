import { NextRequest, NextResponse } from "next/server";
import { getAccessToken } from "@/lib/supabase/server";
import { isSameOrigin } from "@/lib/bff/csrf";
import { isUuid, serializeWorkspaceCookie } from "@/lib/workspace";

// Sets the server-signed workspace-selection cookie. Cookie-authenticated +
// mutating, so it enforces the same-origin (CSRF) check. Backend membership
// remains authoritative — an invalid selection just yields 403 on later calls.
export async function POST(req: NextRequest): Promise<NextResponse> {
  if (!isSameOrigin(req)) {
    return NextResponse.json(
      { error: { code: "forbidden", message: "Cross-origin request rejected." } },
      { status: 403 },
    );
  }
  if (!(await getAccessToken())) {
    return NextResponse.json(
      { error: { code: "unauthorized", message: "Not authenticated." } },
      { status: 401 },
    );
  }
  const body = (await req.json().catch(() => null)) as { workspace_id?: string } | null;
  const workspaceId = body?.workspace_id;
  if (!workspaceId || !isUuid(workspaceId)) {
    return NextResponse.json(
      { error: { code: "validation_error", message: "workspace_id must be a UUID." } },
      { status: 422 },
    );
  }
  const res = NextResponse.json({ ok: true });
  const cookie = serializeWorkspaceCookie(workspaceId);
  res.cookies.set(cookie.name, cookie.value, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
  });
  return res;
}
