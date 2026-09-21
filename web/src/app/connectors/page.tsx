"use client";

import { AppShell } from "@/components/AppShell";
import { ConnectorForm } from "@/components/ConnectorForm";
import { ErrorBanner, Empty, Loading, RoleGate, StatusBadge, canApprove } from "@/components/ui";
import { useConnectors, useCurrentWorkspace } from "@/lib/api/hooks";

export default function ConnectorsPage() {
  const connectors = useConnectors();
  const current = useCurrentWorkspace();
  const role = current.data?.role;

  return (
    <AppShell>
      <h1>Connectors</h1>
      {connectors.isLoading ? <Loading /> : null}
      <ErrorBanner error={connectors.error} />

      {connectors.data && connectors.data.length === 0 ? (
        <Empty>No connectors yet. Add one below.</Empty>
      ) : null}

      {connectors.data && connectors.data.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Status</th>
              <th>Secret</th>
            </tr>
          </thead>
          <tbody>
            {connectors.data.map((c) => (
              <tr key={c.id}>
                <td>{c.name}</td>
                <td>{c.type}</td>
                <td>
                  <StatusBadge status={c.status} />
                </td>
                <td className="muted">{c.has_secret ? "configured" : "none"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {/* Creating a connector attaches a credential and is admin/owner-only.
          This gate is usability only; the API and PostgreSQL RLS are the
          authoritative boundary. */}
      <RoleGate role={role} allow={["owner", "admin"]}>
        <ConnectorForm />
      </RoleGate>
      {role && !canApprove(role) ? (
        <p className="muted">An admin or owner must add or configure connectors.</p>
      ) : null}
    </AppShell>
  );
}
