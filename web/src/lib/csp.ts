// Content-Security-Policy builder.
//
// - connect-src allows the browser to reach the configured Supabase Auth origin
//   (cross-origin) without weakening the policy — no wildcards.
// - script-src uses a per-request NONCE + 'strict-dynamic' (never 'unsafe-inline')
//   so Next.js's inline bootstrap/hydration scripts execute while arbitrary
//   inline scripts remain blocked. The nonce is generated per request in proxy.ts.

/** Safe origin extraction from a URL, or null if absent/invalid. */
export function supabaseOrigin(url: string | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/**
 * Build the CSP string. When a nonce is provided, script-src becomes
 * `'self' 'nonce-<n>' 'strict-dynamic'`; otherwise it falls back to `'self'`.
 */
export function buildContentSecurityPolicy(
  supabaseUrl: string | undefined,
  nonce?: string,
): string {
  const origin = supabaseOrigin(supabaseUrl);
  const connectSrc = ["'self'", ...(origin ? [origin] : [])].join(" ");
  const scriptSrc = nonce ? `'self' 'nonce-${nonce}' 'strict-dynamic'` : "'self'";
  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
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
