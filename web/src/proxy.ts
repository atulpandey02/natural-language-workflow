import { NextResponse, type NextRequest } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { WORKSPACE_COOKIE_NAME } from "@/lib/workspace";

// Next.js 16 proxy (formerly middleware): refreshes the Supabase session on
// every request and enforces the route-protection boundary. API routes handle
// their own auth (returning JSON 401), so they are skipped here.

const PUBLIC_PATHS = ["/login"];

export async function proxy(request: NextRequest): Promise<NextResponse> {
  const response = NextResponse.next({ request });

  const supabase = createServerClient(
    process.env.SUPABASE_SERVER_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
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
