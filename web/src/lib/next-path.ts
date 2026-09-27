// Post-login return path. Only ONE destination may be carried through sign-in:
// the invitation-accept page (so a signed-out invitee does not lose the one-time
// link). Anything else — other paths, absolute/protocol-relative URLs, encoded
// tricks — is dropped, so this can never become an open redirect.

const ACCEPT_PATH = "/invitations/accept";
const TOKEN_RE = /^[A-Za-z0-9_\-.~%]{1,512}$/;

/** A safe `next` value, or null. Accepts only `/invitations/accept?token=<token>`. */
export function safeNextPath(raw: string | null | undefined): string | null {
  if (!raw || raw.length > 700) return null;
  if (!raw.startsWith(`${ACCEPT_PATH}?token=`)) return null;
  if (raw.includes("//") || raw.includes("\\") || raw.includes("#")) return null;
  const token = raw.slice(`${ACCEPT_PATH}?token=`.length);
  if (!TOKEN_RE.test(token) || token.includes("&")) return null;
  return raw;
}

/**
 * Search string for the /login redirect of an unauthenticated request. Only the
 * accept page carries its own path+query forward (as `next`); every other page
 * starts sign-in clean, so no query string ever leaks into the login URL.
 */
export function loginSearchFor(pathname: string, search: string): string {
  if (pathname !== ACCEPT_PATH) return "";
  const next = safeNextPath(`${pathname}${search}`);
  return next ? `?next=${encodeURIComponent(next)}` : "";
}
