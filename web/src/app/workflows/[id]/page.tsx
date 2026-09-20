"use client";

import Link from "next/link";
import { use, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { ScheduleForm } from "@/components/ScheduleForm";
import { ErrorBanner, Empty, Loading, RoleGate, StatusBadge } from "@/components/ui";
import {
  useCreateRun,
  useCurrentWorkspace,
  useRuns,
  useSchedules,
  useWorkflow,
} from "@/lib/api/hooks";

export default function WorkflowDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const workflow = useWorkflow(id);
  const runs = useRuns(id);
  const schedules = useSchedules();
  const current = useCurrentWorkspace();
  const createRun = useCreateRun(id);

  // One idempotency key per "run intent": rapid double-clicks reuse it, so the
  // backend creates exactly one durable run (M10 change #13). Rotated on success.
  const runKey = useRef<string>(crypto.randomUUID());

  const [runError, setRunError] = useState<unknown>(null);

  async function runNow() {
    setRunError(null);
    try {
      const result = await createRun.mutateAsync(runKey.current);
      runKey.current = crypto.randomUUID();
      router.push(`/runs/${result.run_id}`);
    } catch (e) {
      setRunError(e);
    }
  }

  const version = workflow.data?.current_version;
  const steps = Array.isArray((version?.plan as { steps?: unknown[] })?.steps)
    ? ((version!.plan as { steps?: Array<Record<string, unknown>> }).steps as Array<
        Record<string, unknown>
      >)
    : [];
  const wfSchedules = (schedules.data ?? []).filter((s) => s.workflow_id === id);

  return (
    <AppShell>
      {workflow.isLoading ? <Loading /> : null}
      <ErrorBanner error={workflow.error} />
      {workflow.data ? (
        <>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <h1>{workflow.data.name}</h1>
            <button onClick={runNow} disabled={createRun.isPending || !version}>
              {createRun.isPending ? "Starting…" : "Run now"}
            </button>
          </div>
          {!version ? <p className="muted">No materialized version to run.</p> : null}
          <ErrorBanner error={runError} />

          <h2>Steps {version ? `(v${version.version})` : ""}</h2>
          {steps.length === 0 ? (
            <Empty>No steps.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Step</th>
                  <th>Tool</th>
                  <th>Connector</th>
                  <th>Depends on</th>
                </tr>
              </thead>
              <tbody>
                {steps.map((s, i) => (
                  <tr key={i}>
                    <td>{String(s.id ?? i)}</td>
                    <td>{String(s.tool ?? "")}</td>
                    <td className="muted">{s.connector ? String(s.connector) : "—"}</td>
                    <td className="muted">
                      {Array.isArray(s.depends_on) && s.depends_on.length
                        ? (s.depends_on as string[]).join(", ")
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <h2>Runs</h2>
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
                {runs.data.map((r) => (
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

          <h2>Schedules</h2>
          {wfSchedules.length === 0 ? <p className="muted">No schedules attached.</p> : null}
          {wfSchedules.map((s) => (
            <div key={s.id} className="card">
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span>
                  {s.frequency} @ {s.timezone} (min {s.minute}
                  {s.hour !== null ? `, hour ${s.hour}` : ""})
                </span>
                <span>
                  <StatusBadge status={s.enabled ? "active" : "disabled"} /> next{" "}
                  {new Date(s.next_run_at).toLocaleString()}
                </span>
              </div>
            </div>
          ))}

          <RoleGate role={current.data?.role} allow={["owner", "admin"]}>
            <ScheduleForm workflowId={id} />
          </RoleGate>
        </>
      ) : null}
    </AppShell>
  );
}
