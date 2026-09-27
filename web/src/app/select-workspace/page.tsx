"use client";

import { useState } from "react";
import { useCreateWorkspace, useWorkspaces } from "@/lib/api/hooks";
import { hardNavigate, postWorkspaceSelection } from "@/lib/workspace-client";
import { ErrorBanner, Loading } from "@/components/ui";
import { roleLabel } from "@/lib/membership";

const JOURNEY = [
  { title: "Ask", body: "Describe a business question in plain language." },
  { title: "Review", body: "Check the proposed steps and the safety checks." },
  { title: "Execute", body: "Run it durably; actions wait for a second approver." },
  { title: "Evidence", body: "Every result links back to the step that produced it." },
];

export default function SelectWorkspacePage() {
  const workspaces = useWorkspaces();
  const createWorkspace = useCreateWorkspace();
  const [name, setName] = useState("");
  const [touched, setTouched] = useState(false);
  const [selectError, setSelectError] = useState<unknown>(null);
  const [opening, setOpening] = useState<string | null>(null);

  async function select(workspaceId: string) {
    setSelectError(null);
    setOpening(workspaceId);
    try {
      await postWorkspaceSelection(workspaceId);
    } catch (e) {
      // Do NOT navigate on failure; surface a safe error.
      setSelectError(e);
      setOpening(null);
      return;
    }
    // Tenant change → full navigation resets router/RSC + TanStack + client state.
    hardNavigate("/");
  }

  const trimmed = name.trim();
  const nameError =
    touched && !trimmed
      ? "Give your workspace a name."
      : trimmed.length > 80
        ? "Use 80 characters or fewer."
        : null;

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!trimmed || trimmed.length > 80 || createWorkspace.isPending) return;
    try {
      const ws = await createWorkspace.mutateAsync(trimmed);
      await select(ws.id);
    } catch {
      /* the mutation's friendly error is rendered below */
    }
  }

  const ready = !workspaces.isLoading && !workspaces.error;
  const has = (workspaces.data?.length ?? 0) > 0;

  return (
    <main className="container onboarding" id="main-content" style={{ maxWidth: 760 }}>
      <p className="brand" aria-label="NLW pilot">
        <span aria-hidden="true">N</span> NLW <small>PILOT</small>
      </p>
      <h1>{has ? "Choose a workspace" : "Welcome to NLW"}</h1>
      <p className="lead muted">
        A workspace is your team&apos;s private space in NLW: its analyses, workflows, connectors,
        approvals and members are visible only to the people in it.
      </p>

      <ol className="steps" aria-label="How NLW works">
        {JOURNEY.map((s) => (
          <li key={s.title}>
            <strong>{s.title}</strong>
            <span>{s.body}</span>
          </li>
        ))}
      </ol>

      {workspaces.isLoading ? <Loading label="Loading your workspaces…" /> : null}
      {workspaces.error ? <ErrorBanner error={workspaces.error} /> : null}
      <ErrorBanner error={selectError} />

      {ready ? (
        <div data-testid="workspace-ready">
          {has ? (
            <section className="card" aria-labelledby="yours-title">
              <h2 id="yours-title">Your workspaces</h2>
              <ul className="workspace-list">
                {workspaces.data!.map((w) => (
                  <li key={w.id} className="row" style={{ justifyContent: "space-between" }}>
                    <span>
                      <strong>{w.name}</strong> <span className="muted">· {roleLabel(w.role)}</span>
                    </span>
                    <button onClick={() => select(w.id)} disabled={opening !== null}>
                      {opening === w.id ? "Opening…" : "Open"}
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ) : (
            <p className="muted" data-testid="no-workspaces">
              You aren&apos;t in a workspace yet. Create one below, or open the invitation link a
              teammate sent you to join theirs.
            </p>
          )}
        </div>
      ) : null}

      <form onSubmit={create} className="card" noValidate aria-labelledby="create-title">
        <h2 id="create-title">{has ? "Create another workspace" : "Create your workspace"}</h2>
        <p className="muted small">
          You&apos;ll be its owner and can invite teammates from Members. Pilot data is synthetic.
        </p>
        <ErrorBanner error={createWorkspace.error} />
        <label htmlFor="ws-name">Workspace name</label>
        <input
          id="ws-name"
          value={name}
          placeholder="e.g. NLW Pilot Workspace"
          onChange={(e) => setName(e.target.value)}
          onBlur={() => setTouched(true)}
          aria-invalid={nameError ? true : undefined}
          aria-describedby={nameError ? "ws-name-error" : undefined}
          maxLength={120}
          required
        />
        {nameError ? (
          <p className="field-error" id="ws-name-error">
            {nameError}
          </p>
        ) : null}
        <div style={{ marginTop: 12 }}>
          <button type="submit" disabled={createWorkspace.isPending || opening !== null}>
            {createWorkspace.isPending ? "Creating…" : "Create and open"}
          </button>
        </div>
      </form>
    </main>
  );
}
