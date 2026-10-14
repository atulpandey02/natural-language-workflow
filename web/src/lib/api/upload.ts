import { RequestInterruptedError, toApiError } from "@/lib/errors";
import type { DatasetVersionOut } from "@/lib/api/types";

export interface UploadProgress {
  loaded: number;
  total: number;
}

/**
 * Send ONE version's CSV bytes through the same-origin BFF. XMLHttpRequest is
 * used only because fetch cannot report upload progress. The body is the file
 * itself (never read or parsed here). Failures become the same ApiError /
 * RequestInterruptedError types every other call uses.
 */
export function uploadContent(
  datasetId: string,
  versionId: string,
  file: Blob,
  onProgress: (p: UploadProgress) => void,
  signal?: AbortSignal,
): Promise<DatasetVersionOut> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", `/api/nlw/datasets/${datasetId}/versions/${versionId}/content`);
    xhr.setRequestHeader("Content-Type", "text/csv");
    xhr.setRequestHeader("Accept", "application/json");
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress({ loaded: e.loaded, total: e.total });
    };
    const interrupted = () => reject(new RequestInterruptedError("PUT"));
    xhr.onerror = interrupted;
    xhr.ontimeout = interrupted;
    xhr.onabort = interrupted;
    xhr.onload = () => {
      let data: unknown = null;
      try {
        data = xhr.responseText ? JSON.parse(xhr.responseText) : null;
      } catch {
        if (xhr.status >= 200 && xhr.status < 300) return interrupted();
      }
      if (xhr.status >= 200 && xhr.status < 300) return resolve(data as DatasetVersionOut);
      reject(
        toApiError(xhr.status, data, xhr.getResponseHeader("X-Request-Id") ?? undefined, "PUT"),
      );
    };
    signal?.addEventListener("abort", () => xhr.abort(), { once: true });
    xhr.send(file);
  });
}

/** The upload limit this deployment advertises (advisory; the API decides). */
export async function fetchUploadLimit(): Promise<number> {
  const res = await fetch("/api/dataset-upload-limit", { cache: "no-store" });
  if (!res.ok) throw toApiError(res.status, await res.json().catch(() => null));
  const body = (await res.json()) as { max_upload_bytes?: unknown };
  const n = body.max_upload_bytes;
  if (typeof n !== "number" || !Number.isInteger(n) || n < 1) throw new Error("bad limit");
  return n;
}
