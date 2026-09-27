// Safe parsing + UX mapping of the backend's machine-readable error envelope
// ({error:{code,message}}) and HTTP status codes.

export interface ApiErrorShape {
  status: number;
  code: string;
  message: string;
  requestId?: string;
  /** 422 field details ({loc, type}); used only to point at fields, never shown raw. */
  details?: unknown;
  /** HTTP method of the failed request: reads can't have changed anything. */
  method?: string;
}

export class ApiError extends Error {
  status: number;
  code: string;
  requestId?: string;
  details?: unknown;
  method?: string;

  constructor(shape: ApiErrorShape) {
    super(shape.message);
    this.name = "ApiError";
    this.status = shape.status;
    this.code = shape.code;
    this.requestId = shape.requestId;
    this.details = shape.details;
    this.method = shape.method;
  }
}

/**
 * The request didn't produce an HTTP response (connection dropped, aborted, or
 * the response body was cut off). For a write, the server may still have
 * committed it, so the outcome is unknown.
 */
export class RequestInterruptedError extends Error {
  method: string;
  constructor(method: string, cause?: unknown) {
    super("request interrupted", { cause });
    this.name = "RequestInterruptedError";
    this.method = method;
  }
}

/** Turn a status + parsed body into an ApiError with a safe message. */
export function toApiError(
  status: number,
  body: unknown,
  requestId?: string,
  method?: string,
): ApiError {
  let code = "error";
  let message = "Something went wrong.";
  let details: unknown;
  if (body && typeof body === "object" && "error" in body) {
    const err = (body as { error?: { code?: string; message?: string; details?: unknown } }).error;
    if (err?.code) code = err.code;
    if (err?.message) message = err.message;
    details = err?.details;
  }
  return new ApiError({ status, code, message, requestId, details, method });
}

/** A human-facing, status-aware summary the UI can show in a banner. */
export function userMessageForStatus(status: number, fallback: string): string {
  switch (status) {
    case 401:
      return "Your session has expired. Please sign in again.";
    case 403:
      return "You do not have permission to do that.";
    case 409:
      return fallback || "That conflicts with the current state.";
    case 422:
      return fallback || "Some input was invalid.";
    case 429:
      return "You are going too fast. Please wait a moment and retry.";
    case 503:
      return "The service is temporarily unavailable. Please retry shortly.";
    default:
      return fallback || "Something went wrong.";
  }
}
