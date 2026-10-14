"use client";

import { useEffect, useId, useMemo, useState, useSyncExternalStore } from "react";
import { useUploadFlow, useUploadLimit } from "@/lib/api/dataset-hooks";
import {
  DEFAULT_MAX_UPLOAD_BYTES,
  OUTCOME_COPY,
  checkFile,
  formatBytes,
  parsePending,
  pendingSnapshot,
} from "@/lib/datasets";

// The record changes only through this tab's own upload flow, which re-renders.
const noSubscription = () => () => {};

function percent(loaded: number, total: number): number {
  return total > 0 ? Math.min(100, Math.round((loaded / total) * 100)) : 0;
}

/**
 * Start a NEW version and send one CSV file. The checks here are advisory
 * (the BFF and the API decide); the file is never read or parsed in the
 * browser. A retry of the same file continues the same version.
 */
export function UploadPanel({
  datasetId,
  onVersion,
}: {
  datasetId: string;
  /** Called with the version this upload created or continued. */
  onVersion: (versionId: string) => void;
}) {
  const limit = useUploadLimit();
  const maxBytes = limit.data ?? DEFAULT_MAX_UPLOAD_BYTES;
  const { state, start, reset, canRetry } = useUploadFlow(datasetId, maxBytes);
  const [file, setFile] = useState<File | null>(null);
  const [advice, setAdvice] = useState<string | null>(null);
  const ids = { file: useId(), hint: useId(), advice: useId() };

  // An upload this tab started but did not finish (e.g. before a reload).
  // sessionStorage is browser-only: the server snapshot is "nothing pending".
  const pendingRaw = useSyncExternalStore(
    noSubscription,
    () => pendingSnapshot(datasetId),
    () => null,
  );
  const resume = useMemo(() => parsePending(pendingRaw), [pendingRaw]);

  useEffect(() => {
    if (state.versionId) onVersion(state.versionId);
  }, [state.versionId, onVersion]);

  const busy = state.phase === "initiating" || state.phase === "uploading";

  function choose(f: File | null) {
    setFile(f);
    reset();
    if (!f) return setAdvice(null);
    const check = checkFile(f, maxBytes);
    setAdvice(check.ok ? null : check.message);
  }

  const announcement =
    state.phase === "initiating"
      ? `Starting a version for ${state.filename}.`
      : state.phase === "uploading"
        ? `Uploading ${state.filename}.`
        : state.phase === "done" && state.outcome === "queued"
          ? `${state.filename} uploaded. Processing is queued.`
          : "";
  const failure =
    state.refused ??
    (state.outcome && state.outcome !== "queued" ? OUTCOME_COPY[state.outcome].title : null);

  return (
    <section className="card" aria-labelledby="upload-title">
      <h2 id="upload-title" style={{ marginTop: 0, fontSize: 16 }}>
        Upload a new version
      </h2>
      <p className="muted small">
        Synthetic data only. Each upload becomes a new version; earlier versions are kept.
      </p>
      {resume && state.phase === "idle" ? (
        <p className="notice" data-testid="resume-notice">
          An upload of “{resume.filename}” ({formatBytes(resume.size)}) did not finish in this tab.
          Choose the same file and upload it again: NLW continues the same version and does not
          create a second one.
        </p>
      ) : null}

      <label htmlFor={ids.file}>CSV file</label>
      <input
        id={ids.file}
        type="file"
        accept=".csv,text/csv"
        disabled={busy}
        aria-describedby={[ids.hint, advice ? ids.advice : null].filter(Boolean).join(" ")}
        aria-invalid={advice ? true : undefined}
        onChange={(e) => choose(e.target.files?.[0] ?? null)}
      />
      <p className="field-hint" id={ids.hint}>
        A .csv file, UTF-8, with a header row. Maximum size: {formatBytes(maxBytes)}.
      </p>
      {advice ? (
        <p className="field-error" id={ids.advice} role="alert">
          {advice}
        </p>
      ) : null}

      <div className="row">
        <button
          type="button"
          disabled={!file || Boolean(advice) || busy}
          onClick={() => file && void start(file)}
        >
          {busy ? "Uploading…" : "Upload"}
        </button>
      </div>

      {state.phase === "uploading" && state.progress ? (
        <div>
          <label htmlFor={`${ids.file}-progress`}>Upload progress</label>{" "}
          <progress
            id={`${ids.file}-progress`}
            max={state.progress.total || 1}
            value={state.progress.loaded}
          />{" "}
          <span className="muted small">
            {percent(state.progress.loaded, state.progress.total)}%
          </span>
        </div>
      ) : null}

      <p className="sr-only" role="status" aria-live="polite" data-testid="upload-status">
        {announcement}
      </p>
      {state.phase === "done" && state.outcome === "queued" ? (
        <p className="muted" data-testid="upload-done">
          Uploaded. Processing is queued; the version below updates on its own.
        </p>
      ) : null}

      {failure ? (
        <div
          className="error-panel"
          role="alert"
          data-testid="upload-outcome"
          data-outcome={state.outcome ?? "refused"}
        >
          <strong>{failure}</strong>
          {state.outcome && state.outcome !== "queued" ? (
            <p>{OUTCOME_COPY[state.outcome].detail}</p>
          ) : (
            <p>Nothing was sent.</p>
          )}
          {canRetry && file ? (
            <button type="button" onClick={() => void start(file)}>
              Try again
            </button>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
