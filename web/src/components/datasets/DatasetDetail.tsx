"use client";

import Link from "next/link";
import { useCallback } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ErrorBanner, Empty, Loading, canApprove } from "@/components/ui";
import { useCurrentWorkspace } from "@/lib/api/hooks";
import { isNotEnabled, useDataset, useDeleteDataset, useVersions } from "@/lib/api/dataset-hooks";
import { STATE_COPY, formatBytes, isMarkedNotQueued, versionState } from "@/lib/datasets";
import { ApiError } from "@/lib/errors";
import { ConfirmAction } from "./ConfirmAction";
import { UploadPanel } from "./UploadPanel";
import { VersionPanel } from "./VersionPanel";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * One dataset: its versions, the upload of a new one (admin/owner) and the
 * selected version (kept in the URL, so a reload returns to it). Role gates
 * here are usability only; the API and RLS are the authoritative boundary.
 */
export function DatasetDetail({ id }: { id: string }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const selectedRaw = params.get("version");
  const selected = selectedRaw && UUID.test(selectedRaw) ? selectedRaw : null;
  const role = useCurrentWorkspace().data?.role;
  const manager = canApprove(role);

  const dataset = useDataset(id);
  const deleting = dataset.data?.status === "DELETING";
  const versions = useVersions(id, Boolean(dataset.data));
  const remove = useDeleteDataset(id);

  const select = useCallback(
    (versionId: string) => {
      router.replace(`${pathname}?version=${versionId}`, { scroll: false });
    },
    [router, pathname],
  );

  if (dataset.error instanceof ApiError && dataset.error.status === 404) {
    return isNotEnabled(dataset.error) ? (
      <Empty>Datasets are not enabled in this environment.</Empty>
    ) : (
      <div className="card" data-testid="dataset-gone">
        <h1 style={{ marginTop: 0 }}>Dataset unavailable</h1>
        <p role="status">
          This dataset does not exist in this workspace, or it is no longer available after a
          deletion request.
        </p>
        <Link href="/datasets">Back to datasets</Link>
      </div>
    );
  }
  if (!dataset.data) {
    return (
      <>
        {dataset.isLoading ? <Loading label="Loading dataset…" /> : null}
        <ErrorBanner error={dataset.error} />
      </>
    );
  }
  const d = dataset.data;

  return (
    <>
      <div className="page-intro">
        <p className="eyebrow">
          <Link href="/datasets">Datasets</Link>
        </p>
        <h1>{d.name}</h1>
        {d.description ? <p className="lead muted">{d.description}</p> : null}
      </div>

      {deleting ? (
        <p className="notice" role="status" data-testid="dataset-deleting">
          Deletion requested. This dataset and its versions can no longer be used. An operator
          removes the stored files in a separate step; this page does not confirm that removal.
        </p>
      ) : null}

      {manager && !deleting ? <UploadPanel datasetId={d.id} onVersion={select} /> : null}
      {!manager ? (
        <p className="muted">An admin or owner uploads files and manages versions.</p>
      ) : null}

      <section aria-labelledby="versions-title">
        <h2 id="versions-title">Versions</h2>
        {versions.isLoading ? <Loading label="Loading versions…" /> : null}
        <ErrorBanner error={versions.error} />
        {versions.data && versions.data.length === 0 ? <Empty>No versions yet.</Empty> : null}
        {versions.data && versions.data.length > 0 ? (
          <div
            className="card table-scroll"
            tabIndex={0}
            role="region"
            aria-label="Versions"
            style={{ padding: 0 }}
          >
            <table>
              <thead>
                <tr>
                  <th>Version</th>
                  <th>File</th>
                  <th>Size</th>
                  <th>State</th>
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {versions.data.map((v) => {
                  const state = versionState(v, { notQueued: isMarkedNotQueued(v.id) });
                  return (
                    <tr key={v.id} aria-current={v.id === selected ? "true" : undefined}>
                      <td>{v.version_number}</td>
                      <td>{v.original_filename}</td>
                      <td>{formatBytes(v.declared_size_bytes)}</td>
                      <td>
                        <span className={`badge ${STATE_COPY[state].tone}`}>
                          {v.status === "PROFILED" ? "Profiled" : STATE_COPY[state].label}
                        </span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="secondary"
                          aria-label={`Open version ${v.version_number}`}
                          onClick={() => select(v.id)}
                        >
                          Open
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      {selected ? (
        <VersionPanel key={selected} datasetId={d.id} versionId={selected} manager={manager} />
      ) : null}

      {manager && !deleting ? (
        <section aria-labelledby="danger-title">
          <h2 id="danger-title">Delete dataset</h2>
          <ConfirmAction
            label="Delete this dataset"
            confirmLabel="Request dataset deletion"
            pending={remove.isPending}
            onConfirm={() => remove.mutate()}
          >
            Deleting makes this dataset and every version unusable immediately. It is a request: an
            operator removes the stored files in a separate step, and this page does not confirm
            that removal.
          </ConfirmAction>
          <ErrorBanner error={remove.error} />
        </section>
      ) : null}
    </>
  );
}
