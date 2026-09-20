"use client";

// Browser reader for the runtime public config. Reads the values the server
// injected into the document (see public-config.ts + app/layout.tsx) instead of
// any build-time NEXT_PUBLIC_* value.

import { PUBLIC_CONFIG_ELEMENT_ID, type PublicConfig } from "./public-config-shared";

let cached: PublicConfig | null = null;

/**
 * Read the runtime public config from the inline data block. Throws if it is
 * missing/invalid — a misconfigured deploy fails loudly rather than silently
 * pointing the browser at the wrong (or no) Supabase project.
 */
export function getBrowserPublicConfig(): PublicConfig {
  if (cached) return cached;
  if (typeof document === "undefined") {
    throw new Error("getBrowserPublicConfig must be called in the browser");
  }
  const el = document.getElementById(PUBLIC_CONFIG_ELEMENT_ID);
  if (!el?.textContent) {
    throw new Error("Runtime public config is missing from the document");
  }
  const parsed = JSON.parse(el.textContent) as PublicConfig;
  if (!parsed.supabaseUrl || !parsed.supabaseAnonKey) {
    throw new Error("Runtime public config is incomplete");
  }
  cached = parsed;
  return cached;
}
