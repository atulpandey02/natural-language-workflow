// Server-side runtime public config. Reads the browser-safe Supabase values from
// the environment AT RUNTIME (never NEXT_PUBLIC_*, never baked into the build), so
// one immutable web image can be pointed at any Supabase project by runtime env.
//
// This module must never be imported into browser code — it reads server-only
// environment. The guard below turns any accidental client import into an
// immediate, obvious error rather than silently shipping env to the bundle.
if (typeof window !== "undefined") {
  throw new Error("public-config.ts (server) must not be imported in the browser");
}

import type { PublicConfig } from "./public-config-shared";

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required runtime environment variable: ${name}`);
  }
  return value;
}

/**
 * The public (browser-facing) config injected into the document. Only the
 * allowlisted public values — never service_role, DB credentials, LLM keys, or
 * connector/worker secrets.
 */
export function getServerPublicConfig(): PublicConfig {
  return {
    supabaseUrl: required("SUPABASE_URL"),
    supabaseAnonKey: required("SUPABASE_ANON_KEY"),
  };
}

/**
 * The URL the Next SERVER uses to reach the SAME Supabase project. Defaults to
 * the public URL; `SUPABASE_SERVER_URL` overrides only the server-side network
 * path (e.g. a private DNS name or host gateway), not which project is used.
 */
export function getServerSupabaseUrl(): string {
  return process.env.SUPABASE_SERVER_URL ?? required("SUPABASE_URL");
}
