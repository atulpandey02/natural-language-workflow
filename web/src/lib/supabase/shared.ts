// A fixed Supabase auth cookie/storage-key name shared by the browser and server
// clients. @supabase/ssr otherwise derives the storage key from the Supabase URL
// host, so if the browser reaches Supabase at one host (e.g. 127.0.0.1) and the
// server at another (e.g. host.docker.internal), the cookie names diverge and the
// server never sees the session. Pinning the name keeps them identical regardless
// of how each side reaches Supabase.
export const SUPABASE_COOKIE_NAME = "sb-nlw-auth";

/**
 * Whether Supabase auth cookies get the `Secure` attribute. In the browser we
 * use the actual page protocol (Secure on HTTPS). On the server we default to
 * Secure and only disable it when `COOKIE_SECURE=false` — set by the e2e HTTP
 * harness (Caddy on :8080) so sign-in works there. Real staging/production is
 * HTTPS, so cookies are Secure on both sides.
 *
 * NOTE (accurate security posture): @supabase/ssr keeps these cookies readable
 * by browser JavaScript (not HttpOnly) because the browser client reads the
 * session. Access tokens are NOT in localStorage, and CSP + CSRF + Secure +
 * SameSite=Lax are the pilot controls. An HttpOnly/opaque server session is a
 * future hardening item (ADR-019).
 */
export function cookieSecure(): boolean {
  if (typeof window !== "undefined") return window.location.protocol === "https:";
  return process.env.COOKIE_SECURE !== "false";
}

/** Shared cookie options for every @supabase/ssr client (pinned name + Secure/SameSite/path). */
export function supabaseCookieOptions() {
  return {
    name: SUPABASE_COOKIE_NAME,
    path: "/",
    sameSite: "lax" as const,
    secure: cookieSecure(),
  };
}
