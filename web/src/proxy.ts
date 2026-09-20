import { NextResponse, type NextRequest } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { WORKSPACE_COOKIE_NAME } from "@/lib/workspace";
import { buildContentSecurityPolicy } from "@/lib/csp";
import { SUPABASE_COOKIE_NAME } from "@/lib/supabase/shared";

// Next.js 16 proxy (formerly middleware): refreshes the Supabase session on
// every request, enforces the route-protection boundary, and sets a per-request
// nonce-based Content-Security-Policy. API routes handle their own auth
// (returning JSON 401), so they are skipped here.

const PUBLIC_PATHS = ["/login"];

export async function proxy(request: NextRequest): Promise<NextResponse> {
  // Per-request script nonce so Next.js's inline bootstrap/hydration scripts
  // execute under a strict CSP without 'unsafe-inline'. Next reads the nonce from
  // the request's Content-Security-Policy header and applies it to its scripts.
  const nonce = btoa(crypto.randomUUID());
  const csp = buildContentSecurityPolicy(process.env.NEXT_PUBLIC_SUPABASE_URL, nonce);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("content-security-policy", csp);

  const supabase = createServerClient(
    process.env.SUPABASE_SERVER_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookieOptions: { name: SUPABASE_COOKIE_NAME },
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(toSet) {
          toSet.forEach(({ name, value, options }) => response.cookies.set(name, value, options));
        },
      },
    },
  );

  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { pathname } = request.nextUrl;
  const isPublic = PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + "/"));

  if (!user && !isPublic) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    return NextResponse.redirect(url);
  }

  // Authenticated but no workspace selected: force selection (except on the
  // selection page itself and public pages).
  if (user && !isPublic && pathname !== "/select-workspace") {
    const hasWorkspace = Boolean(request.cookies.get(WORKSPACE_COOKIE_NAME)?.value);
    if (!hasWorkspace) {
      const url = request.nextUrl.clone();
      url.pathname = "/select-workspace";
      return NextResponse.redirect(url);
    }
  }

  return response;
}

export const config = {
  // Run on pages only; exclude API routes (they self-authenticate) and static.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
