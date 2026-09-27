import { RequestInterruptedError, toApiError } from "@/lib/errors";

// Browser -> same-origin BFF client. Never talks to FastAPI directly and never
// handles bearer tokens (the BFF injects them server-side). Centralizes base
// path, JSON handling, safe error parsing, and request-id visibility.

const BASE = "/api/nlw";

interface RequestOptions {
  body?: unknown;
  idempotencyKey?: string;
  signal?: AbortSignal;
}

async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  let body: string | undefined;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;

  let res: Response;
  let text: string;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body,
      signal: opts.signal,
      cache: "no-store",
    });
    text = await res.text();
  } catch (cause) {
    // No complete response: for a write, the server may still have committed it.
    throw new RequestInterruptedError(method, cause);
  }
  const requestId = res.headers.get("X-Request-Id") ?? undefined;
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (cause) {
    if (res.ok) throw new RequestInterruptedError(method, cause);
  }
  if (!res.ok) {
    throw toApiError(res.status, data, requestId, method);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>("GET", path, { signal }),
  post: <T>(path: string, body?: unknown, idempotencyKey?: string) =>
    request<T>("POST", path, { body, idempotencyKey }),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, { body }),
  del: <T>(path: string) => request<T>("DELETE", path),
};
