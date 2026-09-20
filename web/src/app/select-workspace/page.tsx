"use client";

import { useState } from "react";
import { useCreateWorkspace, useWorkspaces } from "@/lib/api/hooks";
import { hardNavigate, postWorkspaceSelection } from "@/lib/workspace-client";
import { ErrorBanner, Loading } from "@/components/ui";

export default function SelectWorkspacePage() {
  const workspaces = useWorkspaces();
  const createWorkspace = useCreateWorkspace();
  const [name, setName] = useState("");
  const [selectError, setSelectError] = useState<unknown>(null);

  async function select(workspaceId: string) {
    setSelectError(null);
    try {
      await postWorkspaceSelection(workspaceId);
    } catch (e) {
      // Do NOT navigate on failure; surface a safe error.
      setSelectError(e);
      return;
    }
    // Tenant change → full navigation resets router/RSC + TanStack + client state.
    hardNavigate("/");
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    const ws = await createWorkspace.mutateAsync(name);
    await select(ws.id);
  }

  const ready = !workspaces.isLoading && !workspaces.error;

  return (
    <main className="container" style={{ maxWidth: 480, paddingTop: 48 }}>
      <h1>Select a workspace</h1>
      {workspaces.isLoading ? <Loading /> : null}
      {workspaces.error ? <ErrorBanner error={workspaces.error} /> : null}
      <ErrorBanner error={selectError} />

      {ready ? (
        <div data-testid="workspace-ready">
          {workspaces.data && workspaces.data.length > 0 ? (
            <div className="card">
              {workspaces.data.map((w) => (
                <div key={w.id} className="row" style={{ justifyContent: "space-between" }}>
                  <span>
                    {w.name} <span className="muted">({w.role})</span>
                  </span>
                  <button onClick={() => select(w.id)}>Open</button>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">You have no workspaces yet. Create one to start.</p>
          )}
        </div>
      ) : null}

      <form onSubmit={create} className="card" noValidate>
        <h2 style={{ marginTop: 0, fontSize: 16 }}>Create a workspace</h2>
        <ErrorBanner error={createWorkspace.error} />
        <label htmlFor="ws-name">Workspace name</label>
        <input
          id="ws-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          minLength={1}
        />
        <div style={{ marginTop: 12 }}>
          <button type="submit" disabled={createWorkspace.isPending || !name.trim()}>
            {createWorkspace.isPending ? "Creating…" : "Create + open"}
          </button>
        </div>
      </form>
    </main>
  );
}
