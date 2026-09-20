// Content-Security-Policy builder. connect-src must allow the browser to reach
// the Supabase Auth origin (cross-origin) WITHOUT weakening the policy — no
// wildcards, no removal of other directives. The exact origin is derived from
// NEXT_PUBLIC_SUPABASE_URL at build time.

/** Safe origin extraction from a URL, or null if absent/invalid. */
export function supabaseOrigin(url: string | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** Build the CSP string, allowing connect-src to the configured Supabase origin. */
export function buildContentSecurityPolicy(supabaseUrl: string | undefined): string {
  const origin = supabaseOrigin(supabaseUrl);
  const connectSrc = ["'self'", ...(origin ? [origin] : [])].join(" ");
  return [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    `connect-src ${connectSrc}`,
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}
