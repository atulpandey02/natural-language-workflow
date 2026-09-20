"use client";

import { useRouter } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { useCurrentWorkspace, useWorkspaces } from "@/lib/api/hooks";

export function WorkspaceSwitcher() {
  const router = useRouter();
  const qc = useQueryClient();
  const workspaces = useWorkspaces();
  const current = useCurrentWorkspace();

  async function select(workspaceId: string) {
    if (!workspaceId || workspaceId === current.data?.tenant_id) return;
    await fetch("/api/workspace", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ workspace_id: workspaceId }),
    });
    // Switching tenants must not show stale previous-tenant data (M10 change #5).
    qc.clear();
    router.refresh();
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
    </label>
  );
}
