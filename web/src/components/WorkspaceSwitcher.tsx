"use client";

import { useState } from "react";
import { useCurrentWorkspace, useWorkspaces } from "@/lib/api/hooks";
import { hardReload, postWorkspaceSelection } from "@/lib/workspace-client";

export function WorkspaceSwitcher() {
  const workspaces = useWorkspaces();
  const current = useCurrentWorkspace();
  const [error, setError] = useState<string | null>(null);

  async function select(workspaceId: string) {
    if (!workspaceId || workspaceId === current.data?.tenant_id) return;
    setError(null);
    try {
      await postWorkspaceSelection(workspaceId);
    } catch {
      // Do not reload on failure; surface safe feedback.
      setError("Could not switch workspace.");
      return;
    }
    // Tenant change is a hard boundary: full reload resets all client state
    // (router/RSC cache + TanStack Query) so no stale previous-tenant data shows.
    hardReload();
  }

  if (workspaces.isLoading) return <span className="muted">workspace…</span>;
  const items = workspaces.data ?? [];
  if (items.length === 0) return null;

  return (
    <label style={{ margin: 0 }}>
      <span className="muted" style={{ marginRight: 6 }}>
        Workspace
      </span>
      <select
        aria-label="Select workspace"
        value={current.data?.tenant_id ?? ""}
        onChange={(e) => select(e.target.value)}
        style={{ width: "auto", display: "inline-block" }}
      >
        {items.map((w) => (
          <option key={w.id} value={w.id}>
            {w.name} ({w.role})
          </option>
        ))}
      </select>
      {error ? (
        <span className="muted" role="alert" style={{ marginLeft: 8, color: "var(--danger)" }}>
          {error}
        </span>
      ) : null}
    </label>
  );
}
