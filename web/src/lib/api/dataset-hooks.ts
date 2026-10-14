"use client";

import { useCallback, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { fetchUploadLimit, uploadContent, type UploadProgress } from "@/lib/api/upload";
import type {
  DatasetOut,
  DatasetVersionOut,
  SemanticColumn,
  SemanticRevisionOut,
} from "@/lib/api/types";
import { ApiError } from "@/lib/errors";
import {
  DEFAULT_MAX_UPLOAD_BYTES,
  checkFile,
  classifyUploadError,
  clearPending,
  idempotencyKeyFor,
  isPollable,
  markNotQueued,
  nextPollDelay,
  savePending,
  type UploadOutcome,
} from "@/lib/datasets";

const keys = {
  list: ["datasets"] as const,
  one: (d: string) => ["dataset", d] as const,
  versions: (d: string) => ["dataset-versions", d] as const,
  version: (d: string, v: string) => ["dataset-version", d, v] as const,
  profile: (d: string, v: string) => ["dataset-profile", d, v] as const,
  semantics: (d: string, v: string) => ["dataset-semantics", d, v] as const,
};

/**
 * A missing ROUTE means the feature is not enabled here (the API and the BFF
 * answer a generic `not_found`); a missing dataset has its own DATASET_* code.
 */
export function isNotEnabled(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404 && error.code === "not_found";
}

/** 403/404 are answers, not transient failures: never retried. */
function retryRead(count: number, error: unknown): boolean {
  if (error instanceof ApiError && error.status < 500) return false;
  return count < 2;
}

export function useDatasets() {
  return useQuery({
    queryKey: keys.list,
    queryFn: () => api.get<DatasetOut[]>("/datasets"),
    retry: retryRead,
  });
}

export function useDataset(id: string) {
  return useQuery({
    queryKey: keys.one(id),
    queryFn: () => api.get<DatasetOut>(`/datasets/${id}`),
    retry: retryRead,
  });
}

export function useVersions(id: string, enabled = true) {
  return useQuery({
    queryKey: keys.versions(id),
    queryFn: () => api.get<DatasetVersionOut[]>(`/datasets/${id}/versions`),
    enabled,
    retry: retryRead,
  });
}

/**
 * One version, polled with bounded backoff while the API may still change it
 * (queued, processing). Polling stops for every settled state and after
 * MAX_POLLS checks; `checkAgain` restarts it after a recovery action.
 */
export function useVersion(datasetId: string, versionId: string | null) {
  const qc = useQueryClient();
  const key = keys.version(datasetId, versionId ?? "none");
  // Status checks are counted from the load (or the last manual "check
  // again"); the first one after it waits the shortest delay.
  const [base, setBase] = useState(0);
  const polls = (count: number) => Math.max(0, count - base - 1);
  const query = useQuery({
    queryKey: key,
    queryFn: () => api.get<DatasetVersionOut>(`/datasets/${datasetId}/versions/${versionId}`),
    enabled: Boolean(versionId),
    retry: retryRead,
    refetchInterval: (q) => nextPollDelay(q.state.data, polls(q.state.dataUpdateCount)),
    refetchIntervalInBackground: false,
  });
  const { refetch } = query;
  const checkAgain = useCallback(() => {
    setBase(qc.getQueryState(key)?.dataUpdateCount ?? 0);
    void refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qc, refetch, datasetId, versionId]);
  // Still in a state the API may change, but the bounded polling has ended:
  // the page offers "check again" instead of polling forever.
  const count = qc.getQueryState(key)?.dataUpdateCount ?? 0;
  const stalled = isPollable(query.data) && nextPollDelay(query.data, polls(count)) === false;
  return { ...query, checkAgain, stalled };
}

export function useProfile(datasetId: string, versionId: string, enabled: boolean) {
  return useQuery({
    queryKey: keys.profile(datasetId, versionId),
    queryFn: () => api.get<unknown>(`/datasets/${datasetId}/versions/${versionId}/profile`),
    enabled,
    retry: retryRead,
  });
}

export function useSemantics(datasetId: string, versionId: string, enabled: boolean) {
  return useQuery({
    queryKey: keys.semantics(datasetId, versionId),
    queryFn: () =>
      api.get<SemanticRevisionOut[]>(`/datasets/${datasetId}/versions/${versionId}/semantics`),
    enabled,
    retry: retryRead,
  });
}

export function useUploadLimit() {
  return useQuery({
    queryKey: ["dataset-upload-limit"],
    queryFn: fetchUploadLimit,
    staleTime: Infinity,
    retry: 1,
  });
}

function useRefresh(datasetId: string) {
  const qc = useQueryClient();
  return useCallback(
    (versionId?: string) => {
      void qc.invalidateQueries({ queryKey: keys.list });
      void qc.invalidateQueries({ queryKey: keys.one(datasetId) });
      void qc.invalidateQueries({ queryKey: keys.versions(datasetId) });
      if (versionId) {
        void qc.invalidateQueries({ queryKey: keys.version(datasetId, versionId) });
        void qc.invalidateQueries({ queryKey: keys.semantics(datasetId, versionId) });
      }
    },
    [qc, datasetId],
  );
}

export function useCreateDataset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; description?: string }) =>
      api.post<DatasetOut>("/datasets", body),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.list }),
  });
}

export function useRequestProcessing(datasetId: string) {
  const refresh = useRefresh(datasetId);
  return useMutation({
    mutationFn: (versionId: string) =>
      api.post<DatasetVersionOut>(`/datasets/${datasetId}/versions/${versionId}/process`),
    onSuccess: (_v, versionId) => markNotQueued(versionId, false),
    onError: (error, versionId) => {
      if (classifyUploadError(error) === "not_queued") markNotQueued(versionId, true);
    },
    onSettled: (_d, _e, versionId) => refresh(versionId),
  });
}

export function useConfirmSemantics(datasetId: string, versionId: string) {
  const refresh = useRefresh(datasetId);
  return useMutation({
    mutationFn: (columns: SemanticColumn[]) =>
      api.post<SemanticRevisionOut>(`/datasets/${datasetId}/versions/${versionId}/semantics`, {
        columns,
      }),
    onSettled: () => refresh(versionId),
  });
}

export function useActivateVersion(datasetId: string, versionId: string) {
  const refresh = useRefresh(datasetId);
  return useMutation({
    mutationFn: () =>
      api.post<DatasetVersionOut>(`/datasets/${datasetId}/versions/${versionId}/activate`),
    onSettled: () => refresh(versionId),
  });
}

export function useDeleteVersion(datasetId: string) {
  const refresh = useRefresh(datasetId);
  return useMutation({
    mutationFn: (versionId: string) =>
      api.del<DatasetVersionOut>(`/datasets/${datasetId}/versions/${versionId}`),
    onSettled: (_d, _e, versionId) => refresh(versionId),
  });
}

export function useDeleteDataset(datasetId: string) {
  const refresh = useRefresh(datasetId);
  return useMutation({
    mutationFn: () => api.del<DatasetOut>(`/datasets/${datasetId}`),
    onSettled: () => refresh(),
  });
}

// --- the upload flow ----------------------------------------------------------

export type UploadPhase = "idle" | "initiating" | "uploading" | "done" | "failed";

export interface UploadState {
  phase: UploadPhase;
  progress: UploadProgress | null;
  /** queued | not_queued after success; the failure class otherwise. */
  outcome: UploadOutcome | null;
  versionId: string | null;
  filename: string | null;
  /** A client-side advisory refusal (nothing was sent). */
  refused: string | null;
}

const IDLE: UploadState = {
  phase: "idle",
  progress: null,
  outcome: null,
  versionId: null,
  filename: null,
  refused: null,
};

const RETRYABLE = new Set<UploadOutcome>(["interrupted", "unknown", "rate_limited"]);

export interface UploadDeps {
  newKey: () => string;
  initiate: (
    datasetId: string,
    body: { original_filename: string; declared_size_bytes: number },
    key: string,
  ) => Promise<DatasetVersionOut>;
  send: typeof uploadContent;
}

const defaultDeps: UploadDeps = {
  newKey: () => crypto.randomUUID(),
  initiate: (datasetId, body, key) =>
    api.post<DatasetVersionOut>(`/datasets/${datasetId}/versions`, body, key),
  send: uploadContent,
};

/**
 * Initiate a version (with an Idempotency-Key remembered for this file) and
 * send its bytes. A retry of the same file reuses the key, so a lost response
 * returns the SAME version instead of creating a second one; if that version
 * already holds the bytes, nothing is sent again.
 */
export function useUploadFlow(datasetId: string, maxBytes: number | undefined, deps = defaultDeps) {
  const [state, setState] = useState<UploadState>(IDLE);
  const refresh = useRefresh(datasetId);
  const busy = useRef(false);

  const start = useCallback(
    async (file: File) => {
      if (busy.current) return;
      const check = checkFile(file, maxBytes ?? DEFAULT_MAX_UPLOAD_BYTES);
      if (!check.ok) {
        setState({ ...IDLE, phase: "failed", refused: check.message, filename: file.name });
        return;
      }
      busy.current = true;
      const pending = idempotencyKeyFor(datasetId, file, deps.newKey);
      setState({ ...IDLE, phase: "initiating", filename: file.name });
      let versionId: string | null = pending.versionId ?? null;
      try {
        const version = await deps.initiate(
          datasetId,
          { original_filename: file.name, declared_size_bytes: file.size },
          pending.key,
        );
        versionId = version.id;
        savePending(datasetId, { ...pending, versionId });
        refresh(versionId);
        if (!version.has_content) {
          setState((s) => ({
            ...s,
            phase: "uploading",
            versionId,
            progress: { loaded: 0, total: file.size },
          }));
          await deps.send(datasetId, versionId, file, (progress) =>
            setState((s) => ({ ...s, progress })),
          );
        }
        clearPending(datasetId);
        markNotQueued(versionId, false);
        setState((s) => ({ ...s, phase: "done", outcome: "queued", versionId }));
      } catch (error) {
        const outcome = classifyUploadError(error);
        if (outcome === "not_queued" && versionId) {
          // Committed: the file is stored and a request recorded; only the
          // queue message is missing. Recovery is "request processing again".
          clearPending(datasetId);
          markNotQueued(versionId, true);
          setState((s) => ({ ...s, phase: "done", outcome, versionId }));
        } else {
          if (!RETRYABLE.has(outcome)) clearPending(datasetId);
          setState((s) => ({ ...s, phase: "failed", outcome, versionId }));
        }
      } finally {
        busy.current = false;
        if (versionId) refresh(versionId);
      }
    },
    [datasetId, maxBytes, deps, refresh],
  );

  const reset = useCallback(() => setState(IDLE), []);
  return { state, start, reset, canRetry: state.outcome !== null && RETRYABLE.has(state.outcome) };
}
