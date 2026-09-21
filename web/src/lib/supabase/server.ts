import { cookies } from "next/headers";
import { createServerClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";
import { getServerPublicConfig, getServerSupabaseUrl } from "../public-config";
import { supabaseCookieOptions } from "./shared";

/**
 * Server-side Supabase client bound to the request cookies. The session lives in
 * cookies managed by @supabase/ssr; application code never reads the access token
 * from localStorage and the browser never calls FastAPI directly (M10 change #1).
 */
export async function getSupabaseServerClient(): Promise<SupabaseClient> {
  const cookieStore = await cookies();
  // Server-side calls may need a different (internal) Supabase URL than the
  // browser — e.g. a private DNS name or host gateway — so getServerSupabaseUrl()
  // prefers SUPABASE_SERVER_URL, falling back to the public URL. Both are read at
  // runtime; the anon key is the same public value the browser uses.
  return createServerClient(getServerSupabaseUrl(), getServerPublicConfig().supabaseAnonKey, {
    cookieOptions: supabaseCookieOptions(),
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(toSet) {
        try {
          toSet.forEach(({ name, value, options }) => cookieStore.set(name, value, options));
        } catch {
          // Called from a Server Component render where cookies are read-only;
          // the proxy boundary refreshes the session instead.
        }
      },
    },
  });
}

/** Resolve the current access token server-side, or null if unauthenticated. */
export async function getAccessToken(): Promise<string | null> {
  const supabase = await getSupabaseServerClient();
  const {
    data: { session },
  } = await supabase.auth.getSession();
  return session?.access_token ?? null;
}
