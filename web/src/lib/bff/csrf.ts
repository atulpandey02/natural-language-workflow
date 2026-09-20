import { NextRequest } from "next/server";

// CSRF defense for cookie-authenticated mutating BFF routes (M10 change #2):
// strict same-origin validation of the Origin (or Referer) against the Host.
// Combined with SameSite cookies, this blocks cross-site forged mutations.

const MUTATING = new Set(["POST", "PATCH", "PUT", "DELETE"]);

export function requiresCsrfCheck(method: string): boolean {
  return MUTATING.has(method.toUpperCase());
}

export function isSameOrigin(req: NextRequest): boolean {
  const host = req.headers.get("host");
  if (!host) return false;
  const source = req.headers.get("origin") ?? req.headers.get("referer");
  if (!source) return false; // mutating requests must present an Origin/Referer
  try {
    return new URL(source).host === host;
  } catch {
    return false;
  }
}
