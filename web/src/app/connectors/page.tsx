"use client";

import { AppShell } from "@/components/AppShell";
import { ConnectorForm } from "@/components/ConnectorForm";
import { ErrorBanner, Empty, Loading, StatusBadge } from "@/components/ui";
import { useConnectors } from "@/lib/api/hooks";

export default function ConnectorsPage() {
  const connectors = useConnectors();

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

      <ConnectorForm />
    </AppShell>
  );
}
