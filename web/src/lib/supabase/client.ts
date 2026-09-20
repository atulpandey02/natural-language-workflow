"use client";

import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";
import { SUPABASE_COOKIE_NAME } from "./shared";

let _client: SupabaseClient | null = null;

/**
 * Browser Supabase client used ONLY for the auth flow (sign in/out) and session
 * cookie management. It is never used to call FastAPI — all data access goes
 * through the same-origin BFF, which injects the bearer token server-side.
 */
export function getSupabaseBrowserClient(): SupabaseClient {
  if (_client) return _client;
  _client = createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookieOptions: { name: SUPABASE_COOKIE_NAME } },
  );
  return _client;
}
