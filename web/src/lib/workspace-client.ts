"use client";

// Client helpers for changing the active workspace. Changing tenant context is a
// hard boundary: after the server-signed cookie is written we do a FULL
// navigation so the Next router/RSC cache, TanStack Query state, and all
// tenant-specific client state are reset (no stale previous-tenant data).

/** POST the workspace selection; throws a safe error if the request fails. */
export async function postWorkspaceSelection(workspaceId: string): Promise<void> {
  const res = await fetch("/api/workspace", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ workspace_id: workspaceId }),
  });
  if (!res.ok) {
    throw new Error("Could not switch workspace. Please try again.");
  }
}

/** Full navigation to a URL (resets all client state). Wrapped for testability. */
export function hardNavigate(url: string): void {
  window.location.assign(url);
}

/** Full reload of the current page (resets all client state). */
export function hardReload(): void {
  window.location.reload();
}
