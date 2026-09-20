"use client";

import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, StatusBadge } from "@/components/ui";
import { useApprovals, useConnectors, useRuns, useSchedules, useWorkflows } from "@/lib/api/hooks";

function StatCard({ label, value, href }: { label: string; value: number | string; href: string }) {
  return (
    <Link href={href} className="card" style={{ flex: "1 1 140px", minWidth: 140 }}>
      <div className="muted">{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700 }}>{value}</div>
    </Link>
  );
}

export default function DashboardPage() {
  const workflows = useWorkflows();
  const runs = useRuns();
  const connectors = useConnectors();
  const approvals = useApprovals();
  const schedules = useSchedules();

  const anyError =
    workflows.error || runs.error || connectors.error || approvals.error || schedules.error;

  return (
    <AppShell>
      <h1>Dashboard</h1>
      <ErrorBanner error={anyError} />
      <div className="row" style={{ alignItems: "stretch" }}>
        <StatCard label="Workflows" value={workflows.data?.length ?? "…"} href="/workflows" />
        <StatCard label="Connectors" value={connectors.data?.length ?? "…"} href="/connectors" />
        <StatCard
          label="Pending approvals"
          value={approvals.data?.length ?? "…"}
          href="/approvals"
        />
        <StatCard label="Schedules" value={schedules.data?.length ?? "…"} href="/schedules" />
      </div>

      <h2>Recent runs</h2>
      {runs.isLoading ? <Loading /> : null}
      {runs.data && runs.data.length === 0 ? <Empty>No runs yet.</Empty> : null}
      {runs.data && runs.data.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Run</th>
              <th>Status</th>
              <th>Trigger</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {runs.data.slice(0, 10).map((r) => (
              <tr key={r.id}>
                <td>
                  <Link href={`/runs/${r.id}`}>{r.id.slice(0, 8)}</Link>
                </td>
                <td>
                  <StatusBadge status={r.status} />
                </td>
                <td>{r.trigger}</td>
                <td className="muted">{new Date(r.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </AppShell>
  );
}
