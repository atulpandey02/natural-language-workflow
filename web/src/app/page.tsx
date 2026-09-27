"use client";

import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, StatusBadge } from "@/components/ui";
import {
  useApprovals,
  useConnectors,
  useCurrentWorkspace,
  useRuns,
  useSchedules,
  useWorkflows,
} from "@/lib/api/hooks";
import { isManager } from "@/lib/membership";
import { GetStarted } from "@/components/GetStarted";
import { HomeComposer } from "@/components/HomeComposer";

function StatCard({
  label,
  value,
  href,
  attention = false,
}: {
  label: string;
  value: number | string;
  href: string;
  attention?: boolean;
}) {
  return (
    <Link href={href} className={`stat-card${attention ? " attention" : ""}`}>
      <span className="muted">{label}</span>
      <strong>{value}</strong>
    </Link>
  );
}

export default function DashboardPage() {
  const current = useCurrentWorkspace();
  const workflows = useWorkflows();
  const runs = useRuns();
  const connectors = useConnectors();
  const approvals = useApprovals();
  const schedules = useSchedules();

  const anyError =
    workflows.error || runs.error || connectors.error || approvals.error || schedules.error;

  const pending = approvals.data?.length ?? 0;

  return (
    <AppShell>
      <div className="page-intro">
        <p className="eyebrow">Workspace overview</p>
        <h1>What would you like to understand?</h1>
        <p className="lead muted">
          Ask in plain language, review the plan, and follow every result back to its evidence.
        </p>
      </div>
      <ErrorBanner error={anyError} />
      <HomeComposer />
      {workflows.data && workflows.data.length === 0 ? (
        <GetStarted canManage={isManager(current.data?.role)} />
      ) : null}
      <h2 className="section-title">At a glance</h2>
      <div className="stat-grid">
        <StatCard label="Workflows" value={workflows.data?.length ?? "…"} href="/workflows" />
        <StatCard label="Connectors" value={connectors.data?.length ?? "…"} href="/connectors" />
        <StatCard
          label="Awaiting approval"
          value={approvals.data ? pending : "…"}
          href="/approvals"
          attention={pending > 0}
        />
        <StatCard label="Schedules" value={schedules.data?.length ?? "…"} href="/schedules" />
      </div>

      <h2 className="section-title">Recent runs</h2>
      {runs.isLoading ? <Loading /> : null}
      {runs.data && runs.data.length === 0 ? (
        <Empty>
          No runs yet. Prepare a plan above, save it as a workflow, then choose Run now.
        </Empty>
      ) : null}
      {runs.data && runs.data.length > 0 ? (
        <div
          className="card table-scroll"
          tabIndex={0}
          role="region"
          aria-label="Recent runs"
          style={{ padding: 0 }}
        >
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
                  <td className="nowrap">
                    <Link href={`/runs/${r.id}`}>Run {r.id.slice(0, 8)}</Link>
                  </td>
                  <td className="nowrap">
                    <StatusBadge status={r.status} />
                  </td>
                  <td>{r.trigger === "schedule" ? "Scheduled" : "Manual"}</td>
                  <td className="muted nowrap">{new Date(r.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </AppShell>
  );
}
