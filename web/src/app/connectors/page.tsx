"use client";

import { AppShell } from "@/components/AppShell";
import { ConnectorForm } from "@/components/ConnectorForm";
import { ErrorBanner, Empty, Loading, RoleGate, StatusBadge, canApprove } from "@/components/ui";
import { useConnectors, useCurrentWorkspace } from "@/lib/api/hooks";

const CONNECTOR_TYPE_LABEL: Record<string, string> = {
  slack: "Slack",
  postgres: "PostgreSQL",
  webhook: "Webhook",
  static: "Static (test)",
};

const NEXT_STEP: Record<string, string> = {
  unchecked: "Your operator provisions and checks the secret.",
  active: "Ready to use in workflows.",
  error: "The last check failed. Ask your operator to verify the secret.",
  disabled: "Disabled. Plans can't use it.",
};

export default function ConnectorsPage() {
  const connectors = useConnectors();
  const current = useCurrentWorkspace();
  const role = current.data?.role;

  return (
    <AppShell>
      <div className="page-intro">
        <p className="eyebrow">Workspace</p>
        <h1>Connectors</h1>
        <p className="lead muted">
          Connectors are the places NLW may read from or share approved results to. Credentials stay
          with your operator: a connector names a secret reference, never the secret itself.
        </p>
      </div>
      {connectors.isLoading ? <Loading /> : null}
      <ErrorBanner error={connectors.error} />

      {connectors.data && connectors.data.length === 0 ? (
        <Empty>No connectors yet. Add one below.</Empty>
      ) : null}

      {connectors.data && connectors.data.length > 0 ? (
        <div
          className="card table-scroll"
          tabIndex={0}
          role="region"
          aria-label="Connectors"
          style={{ padding: 0 }}
        >
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Status</th>
                <th>Secret</th>
                <th>Next step</th>
              </tr>
            </thead>
            <tbody>
              {connectors.data.map((c) => (
                <tr key={c.id}>
                  <td>
                    <strong>{c.name}</strong>
                  </td>
                  <td>{CONNECTOR_TYPE_LABEL[c.type] ?? "Other"}</td>
                  <td>
                    <StatusBadge status={c.status} />
                  </td>
                  <td className="muted">{c.has_secret ? "Reference set" : "None"}</td>
                  <td className="muted small">
                    {NEXT_STEP[c.status] ?? "Check with your operator."}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
