"use client";

import { ErrorBanner, Loading } from "@/components/ui";
import {
  useActivateVersion,
  useDeleteVersion,
  useProfile,
  useRequestProcessing,
  useSemantics,
  useVersion,
} from "@/lib/api/dataset-hooks";
import {
  STATE_COPY,
  isMarkedNotQueued,
  profileView,
  rejectionReason,
  versionState,
} from "@/lib/datasets";
import { ApiError } from "@/lib/errors";
import { ConfirmAction } from "./ConfirmAction";
import { ProfileTable } from "./ProfileTable";
import { SemanticsForm } from "./SemanticsForm";

/**
 * One version: its state (polled while the API may still change it), the
 * recovery action for a file that is stored but not processing, and for an
 * admin or owner the profile, column meanings, activation and deletion.
 */
export function VersionPanel({
  datasetId,
  versionId,
  manager,
}: {
  datasetId: string;
  versionId: string;
  manager: boolean;
}) {
  const version = useVersion(datasetId, versionId);
  const v = version.data;
  const profiled = Boolean(v && ["PROFILED", "ACTIVE", "SUPERSEDED"].includes(v.status));
  // Profile and semantics are admin/owner-only in the API; members never ask.
  const profile = useProfile(datasetId, versionId, manager && profiled);
  const semantics = useSemantics(datasetId, versionId, manager && profiled);
  const processing = useRequestProcessing(datasetId);
  const activate = useActivateVersion(datasetId, versionId);
  const remove = useDeleteVersion(datasetId);

  if (version.error instanceof ApiError && version.error.status === 404) {
    return (
      <section className="card" aria-labelledby="version-title" data-testid="version-gone">
        <h2 id="version-title" style={{ marginTop: 0, fontSize: 16 }}>
          Version unavailable
        </h2>
        <p role="status">
          This version does not exist in this workspace, or it is no longer available after a
          deletion request.
        </p>
      </section>
    );
  }
  if (!v) {
    return (
      <section className="card">
        {version.isLoading ? <Loading label="Loading version…" /> : null}
        <ErrorBanner error={version.error} />
      </section>
    );
  }

  const revisions = semantics.data ?? [];
  const latest = revisions.length ? revisions[revisions.length - 1] : undefined;
  const state = versionState(v, {
    notQueued: isMarkedNotQueued(v.id),
    semanticRevisions: revisions.length,
  });
  const copy = STATE_COPY[state];
  const view = profileView(profile.data);
  const canRecover = manager && (state === "queued" || state === "not_queued");
  const canDelete = manager && state !== "deleting";

  return (
    <section className="card" aria-labelledby="version-title" data-testid="version-panel">
      <h2 id="version-title" style={{ marginTop: 0, fontSize: 16 }}>
        Version {v.version_number}: {v.original_filename}
      </h2>
      <p>
        <span className={`badge ${copy.tone}`} data-state={state} data-testid="version-state">
          {copy.label}
        </span>
      </p>
      {/* One polite live region: a state change is announced once. */}
      <p role="status" aria-live="polite" data-testid="version-status">
        {copy.detail}
        {state === "rejected" ? ` ${rejectionReason(v.rejection_code)}` : ""}
      </p>

      {version.stalled ? (
        <p className="notice" data-testid="stalled">
          This is taking longer than expected, so the page stopped checking.{" "}
          <button type="button" className="secondary" onClick={version.checkAgain}>
            Check again
          </button>
        </p>
      ) : null}

      {canRecover ? (
        <div className="row">
          <button
            type="button"
            className={state === "not_queued" ? undefined : "secondary"}
            disabled={processing.isPending}
            onClick={() => processing.mutate(v.id, { onSettled: () => version.checkAgain() })}
          >
            Request processing again
          </button>
          <span className="muted small">
            Safe to repeat: it re-queues the same version and never creates a new one.
          </span>
        </div>
      ) : null}
      <ErrorBanner error={processing.error} />

      {manager && profiled ? (
        <>
          {profile.isLoading ? <Loading label="Loading profile…" /> : null}
          <ErrorBanner error={profile.error} />
          {profile.data !== undefined && !view ? (
            <p className="notice">This profile is in a format this page cannot show.</p>
          ) : null}
          {view ? <ProfileTable profile={view} /> : null}
          {view &&
          semantics.isSuccess &&
          (state === "awaiting_semantics" || state === "ready_to_activate") ? (
            <SemanticsForm datasetId={datasetId} versionId={v.id} profile={view} latest={latest} />
          ) : null}
        </>
      ) : null}

      {manager && state === "ready_to_activate" ? (
        <div className="row">
          <button type="button" disabled={activate.isPending} onClick={() => activate.mutate()}>
            {activate.isPending ? "Activating…" : "Activate this version"}
          </button>
        </div>
      ) : null}
      <ErrorBanner error={activate.error} />

      {!manager ? (
        <p className="muted small">
          An admin or owner reviews the profile, confirms column meanings and activates versions.
        </p>
      ) : null}

      {canDelete ? (
        <div className="row">
          <ConfirmAction
            label="Delete this version"
            confirmLabel="Request deletion"
            pending={remove.isPending}
            onConfirm={() => remove.mutate(v.id)}
          >
            Deleting makes this version unusable immediately. It is a request: an operator removes
            the stored file in a separate step, and this page does not confirm that removal.
          </ConfirmAction>
        </div>
      ) : null}
      <ErrorBanner error={remove.error} />
    </section>
  );
}
