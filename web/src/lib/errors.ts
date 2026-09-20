// Safe parsing + UX mapping of the backend's machine-readable error envelope
// ({error:{code,message}}) and HTTP status codes.

export interface ApiErrorShape {
  status: number;
  code: string;
  message: string;
  requestId?: string;
}

export class ApiError extends Error {
  status: number;
  code: string;
  requestId?: string;

  constructor(shape: ApiErrorShape) {
    super(shape.message);
    this.name = "ApiError";
    this.status = shape.status;
    this.code = shape.code;
    this.requestId = shape.requestId;
  }
}

/** Turn a status + parsed body into an ApiError with a safe message. */
export function toApiError(status: number, body: unknown, requestId?: string): ApiError {
  let code = "error";
  let message = "Something went wrong.";
  if (body && typeof body === "object" && "error" in body) {
    const err = (body as { error?: { code?: string; message?: string } }).error;
    if (err?.code) code = err.code;
    if (err?.message) message = err.message;
  }
  return new ApiError({ status, code, message, requestId });
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
