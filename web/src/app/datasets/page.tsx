"use client";

import Link from "next/link";
import { useState } from "react";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, RoleGate, canApprove } from "@/components/ui";
import { useCurrentWorkspace } from "@/lib/api/hooks";
import { isNotEnabled, useCreateDataset, useDatasets } from "@/lib/api/dataset-hooks";

function CreateDatasetForm() {
  const create = useCreateDataset();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [created, setCreated] = useState<{ id: string; name: string } | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (create.isPending || !name.trim()) return;
    try {
      const d = await create.mutateAsync({
        name: name.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
      });
      setCreated({ id: d.id, name: d.name });
      setName("");
      setDescription("");
    } catch {
      // Shown by ErrorBanner.
    }
  }

  return (
    <form className="card" onSubmit={submit} aria-labelledby="create-dataset-title" noValidate>
      <h2 id="create-dataset-title" style={{ marginTop: 0, fontSize: 16 }}>
        Create a dataset
      </h2>
      <ErrorBanner error={create.error} />
      <p role="status" aria-live="polite" className="muted">
        {created ? (
          <>
            Dataset “{created.name}” created. <Link href={`/datasets/${created.id}`}>Open it</Link>{" "}
            to upload a CSV file.
          </>
        ) : null}
      </p>
      <label htmlFor="ds-name">Name</label>
      <input
        id="ds-name"
        value={name}
        maxLength={200}
        required
        onChange={(e) => setName(e.target.value)}
      />
      <label htmlFor="ds-description">Description (optional)</label>
      <input
        id="ds-description"
        value={description}
        maxLength={1000}
        onChange={(e) => setDescription(e.target.value)}
      />
      <div className="row">
        <button type="submit" disabled={create.isPending || !name.trim()}>
          {create.isPending ? "Creating…" : "Create dataset"}
        </button>
      </div>
    </form>
  );
}

export default function DatasetsPage() {
  const datasets = useDatasets();
  const role = useCurrentWorkspace().data?.role;
  const disabled = isNotEnabled(datasets.error);

  return (
    <AppShell>
      <div className="page-intro">
        <p className="eyebrow">Workspace</p>
        <h1>Datasets</h1>
        <p className="lead muted">
          Upload synthetic CSV files as versioned datasets. Each file is checked and profiled before
          anyone can use it; only structure and counts are shown, never its values.
        </p>
      </div>
      {datasets.isLoading ? <Loading /> : null}
      {disabled ? (
        <Empty>Datasets are not enabled in this environment.</Empty>
      ) : (
        <ErrorBanner error={datasets.error} />
      )}

      {datasets.data && datasets.data.length === 0 ? <Empty>No datasets yet.</Empty> : null}
      {datasets.data && datasets.data.length > 0 ? (
        <div
          className="card table-scroll"
          tabIndex={0}
          role="region"
          aria-label="Datasets"
          style={{ padding: 0 }}
        >
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Versions</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {datasets.data.map((d) => (
                <tr key={d.id}>
                  <td>
                    <Link href={`/datasets/${d.id}`}>{d.name}</Link>
                  </td>
                  <td>{d.version_count}</td>
                  <td>
                    {d.status === "DELETING"
                      ? "Deletion requested"
                      : d.active_version_id
                        ? "Active version available"
                        : "No active version"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {!disabled ? (
        <>
          <RoleGate role={role} allow={["owner", "admin"]}>
            <CreateDatasetForm />
          </RoleGate>
          {role && !canApprove(role) ? (
            <p className="muted">An admin or owner creates datasets and uploads files.</p>
          ) : null}
        </>
      ) : null}
    </AppShell>
  );
}
