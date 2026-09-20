"use client";

import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, RoleGate, StatusBadge } from "@/components/ui";
import { useCurrentWorkspace, useSchedules, useUpdateSchedule } from "@/lib/api/hooks";

export default function SchedulesPage() {
  const schedules = useSchedules();
  const current = useCurrentWorkspace();
  const update = useUpdateSchedule();
  const role = current.data?.role;

  return (
    <AppShell>
      <h1>Schedules</h1>
      {schedules.isLoading ? <Loading /> : null}
      <ErrorBanner error={schedules.error} />
      <ErrorBanner error={update.error} />
      <p className="muted">Attach a schedule from a workflow&apos;s detail page.</p>

      {schedules.data && schedules.data.length === 0 ? <Empty>No schedules yet.</Empty> : null}

      {schedules.data && schedules.data.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Workflow</th>
              <th>Recurrence</th>
              <th>Next run</th>
              <th>State</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {schedules.data.map((s) => (
              <tr key={s.id}>
                <td>
                  <Link href={`/workflows/${s.workflow_id}`}>{s.workflow_id.slice(0, 8)}</Link>
                </td>
                <td>
                  {s.frequency} @ {s.timezone} (min {s.minute}
                  {s.hour !== null ? `, hour ${s.hour}` : ""}
                  {s.day_of_week !== null ? `, dow ${s.day_of_week}` : ""})
                </td>
                <td className="muted">{new Date(s.next_run_at).toLocaleString()}</td>
                <td>
                  <StatusBadge status={s.enabled ? "active" : "disabled"} />
                </td>
                <td>
                  <RoleGate role={role} allow={["owner", "admin"]}>
                    <button
                      className="secondary"
                      onClick={() => update.mutate({ id: s.id, body: { enabled: !s.enabled } })}
                      disabled={update.isPending}
                    >
                      {s.enabled ? "Disable" : "Enable"}
                    </button>
                  </RoleGate>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </AppShell>
  );
}
