"use client";
import Link from "next/link";
import { AppShell } from "@/components/AppShell";
import { Empty, ErrorBanner, Loading, StatusBadge } from "@/components/ui";
import { useRuns } from "@/lib/api/hooks";
export default function RunsPage() {
  const runs = useRuns();
  return (
    <AppShell>
      <p className="eyebrow">EXECUTION HISTORY</p>
      <h1>Runs</h1>
      <ErrorBanner error={runs.error} />
      {runs.isLoading ? <Loading /> : null}
      {runs.data?.length === 0 ? (
        <Empty>No runs yet. Start an accepted workflow to see its progress here.</Empty>
      ) : null}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Run</th>
              <th>Status</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {runs.data?.map((r) => (
              <tr key={r.id}>
                <td>
                  <Link href={`/runs/${r.id}`}>{r.id.slice(0, 8)}</Link>
                </td>
                <td>
                  <StatusBadge status={r.status} />
                </td>
                <td>{new Date(r.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </AppShell>
  );
}
