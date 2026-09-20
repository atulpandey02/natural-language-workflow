import { NextRequest, NextResponse } from "next/server";
import { getAccessToken } from "@/lib/supabase/server";
import { getSelectedWorkspace } from "@/lib/workspace";
import { isAllowed } from "@/lib/bff/allowlist";
import { isSameOrigin, requiresCsrfCheck } from "@/lib/bff/csrf";

const API_URL = process.env.NLW_API_URL ?? "http://localhost:8000";

function errorJson(status: number, code: string, message: string): NextResponse {
  return NextResponse.json({ error: { code, message } }, { status });
}

/**
 * Core BFF handler. The browser calls /api/nlw/<backend-path>; this resolves the
 * session, enforces CSRF + the path/method allowlist, and forwards to FastAPI
 * with a FRESH header set. The browser can never override Authorization,
 * X-Workspace-Id, Host, or forwarded headers — the BFF injects them itself
 * (M10 change #3). Authenticated proxying is always no-store (M10 change #4).
 */
export async function proxy(req: NextRequest, backendPath: string): Promise<NextResponse> {
  const method = req.method.toUpperCase();

  if (!isAllowed(method, backendPath)) {
    return errorJson(404, "not_found", "Unknown resource.");
  }

  if (requiresCsrfCheck(method) && !isSameOrigin(req)) {
    return errorJson(403, "forbidden", "Cross-origin request rejected.");
  }

  const token = await getAccessToken();
  if (!token) {
    return errorJson(401, "unauthorized", "Not authenticated.");
  }

  // Build a fresh, minimal header set. Only safe request headers are forwarded.
  const headers = new Headers();
  headers.set("Authorization", `Bearer ${token}`);
  headers.set("Accept", "application/json");
  const workspace = await getSelectedWorkspace();
  if (workspace) headers.set("X-Workspace-Id", workspace);

  const contentType = req.headers.get("content-type");
  if (contentType) headers.set("Content-Type", contentType);
  const idempotencyKey = req.headers.get("idempotency-key");
  if (idempotencyKey) headers.set("Idempotency-Key", idempotencyKey);

  const url = new URL(req.url);
  const target = `${API_URL}${backendPath}${url.search}`;
  const body = method === "GET" || method === "HEAD" ? undefined : await req.text();

  let upstream: Response;
  try {
    upstream = await fetch(target, { method, headers, body, cache: "no-store" });
  } catch {
    return errorJson(503, "service_unavailable", "Upstream service is unavailable.");
  }

  const payload = await upstream.text();
  const res = new NextResponse(payload, { status: upstream.status });
  // Forward only safe response headers.
  const upstreamType = upstream.headers.get("content-type");
  res.headers.set("Content-Type", upstreamType ?? "application/json");
  const requestId = upstream.headers.get("x-request-id");
  if (requestId) res.headers.set("X-Request-Id", requestId);
  res.headers.set("Cache-Control", "no-store");
  return res;
}
