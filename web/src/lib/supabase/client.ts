"use client";

import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";
import { getBrowserPublicConfig } from "../public-config.client";
import { SUPABASE_COOKIE_NAME } from "./shared";

let _client: SupabaseClient | null = null;

/**
 * Browser Supabase client used ONLY for the auth flow (sign in/out) and session
 * cookie management. It is never used to call FastAPI — all data access goes
 * through the same-origin BFF, which injects the bearer token server-side.
 *
 * The URL + anon key come from the RUNTIME public config injected by the server
 * (never a build-time NEXT_PUBLIC_* value), so one image serves any project.
 */
export function getSupabaseBrowserClient(): SupabaseClient {
  if (_client) return _client;
  const { supabaseUrl, supabaseAnonKey } = getBrowserPublicConfig();
  _client = createBrowserClient(supabaseUrl, supabaseAnonKey, {
    cookieOptions: { name: SUPABASE_COOKIE_NAME },
  });
  return _client;
}
