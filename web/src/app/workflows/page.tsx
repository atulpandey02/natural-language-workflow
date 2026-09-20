"use client";

import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading } from "@/components/ui";
import { useWorkflows } from "@/lib/api/hooks";

export default function WorkflowsPage() {
  const workflows = useWorkflows();

  return (
    <AppShell>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h1>Workflows</h1>
        <Link href="/workflows/new">
          <button>New workflow</button>
        </Link>
      </div>
      {workflows.isLoading ? <Loading /> : null}
      <ErrorBanner error={workflows.error} />

      {workflows.data && workflows.data.length === 0 ? (
        <Empty>
          No workflows yet. <Link href="/workflows/new">Describe one</Link> to get started.
        </Empty>
      ) : null}

      {workflows.data && workflows.data.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {workflows.data.map((w) => (
              <tr key={w.id}>
                <td>
                  <Link href={`/workflows/${w.id}`}>{w.name}</Link>
                </td>
                <td className="muted">{w.current_version_id ? "pinned" : "none"}</td>
                <td className="muted">{new Date(w.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </AppShell>
  );
}
