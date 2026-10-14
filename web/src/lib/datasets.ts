// Dataset upload journey: pure, framework-free rules. The API is the only
// authority (status, roles, limits, validation); everything here decides what
// to SHOW and which safe next step to offer. Nothing here profiles a file,
// reads its contents, or invents a status the API did not return.
import { ApiError, RequestInterruptedError } from "@/lib/errors";
import type {
  DatasetVersionOut,
  ProfileColumnView,
  ProfileView,
  SemanticColumn,
  SemanticRole,
  SemanticType,
} from "@/lib/api/types";

// --- UI states --------------------------------------------------------------

/** Every state the version screen can be in. */
export type VersionUiState =
  | "not_uploaded"
  | "uploading"
  | "queued"
  | "not_queued"
  | "processing"
  | "awaiting_semantics"
  | "ready_to_activate"
  | "active"
  | "superseded"
  | "rejected"
  | "deleting";

export interface StateContext {
  /** Bytes are being sent from this browser right now. */
  uploading?: boolean;
  /** The upload committed but the API said processing was NOT queued. */
  notQueued?: boolean;
  /** Confirmed semantic revisions for this version (0 = none yet). */
  semanticRevisions?: number;
}

/** Map the API's version record (plus what this browser knows) to a UI state. */
export function versionState(v: DatasetVersionOut, ctx: StateContext = {}): VersionUiState {
  switch (v.status) {
    case "DELETING":
      return "deleting";
    case "REJECTED":
      return "rejected";
    case "ACTIVE":
      return "active";
    case "SUPERSEDED":
      return "superseded";
    case "PROFILED":
      return (ctx.semanticRevisions ?? 0) > 0 ? "ready_to_activate" : "awaiting_semantics";
    case "PROFILING":
      return "processing";
    case "QUARANTINED":
      if (!v.has_content) return ctx.uploading ? "uploading" : "not_uploaded";
      return ctx.notQueued ? "not_queued" : "queued";
  }
}

export interface StateCopy {
  label: string;
  /** One plain sentence: what is happening and what happens next. */
  detail: string;
  tone: "ok" | "run" | "warn" | "fail" | "skip";
}

export const STATE_COPY: Record<VersionUiState, StateCopy> = {
  not_uploaded: {
    label: "Not uploaded",
    detail: "This version is waiting for its CSV file.",
    tone: "skip",
  },
  uploading: { label: "Uploading", detail: "Sending the file to NLW.", tone: "run" },
  queued: {
    label: "Queued",
    detail: "The file is stored and waiting to be checked and profiled.",
    tone: "run",
  },
  not_queued: {
    label: "Processing not queued",
    detail:
      "The file is stored and processing was requested, but it could not be queued. " +
      "Nothing was lost: request processing again.",
    tone: "warn",
  },
  processing: {
    label: "Processing",
    detail: "The file is being checked and profiled. This page updates on its own.",
    tone: "run",
  },
  awaiting_semantics: {
    label: "Profiled",
    detail: "The profile is ready. Confirm what each column means before activating.",
    tone: "warn",
  },
  ready_to_activate: {
    label: "Ready to activate",
    detail: "Column meanings are confirmed. Activate this version to make it available.",
    tone: "ok",
  },
  active: { label: "Active", detail: "This is the dataset's current version.", tone: "ok" },
  superseded: {
    label: "Superseded",
    detail: "A newer version was activated after this one.",
    tone: "skip",
  },
  rejected: {
    label: "Rejected",
    detail: "The file was refused. Fix it and upload it as a new version.",
    tone: "fail",
  },
  deleting: {
    label: "Deletion requested",
    detail:
      "This version can no longer be used. An operator removes the stored file " +
      "separately; this page does not confirm that removal.",
    tone: "warn",
  },
};

// --- polling ----------------------------------------------------------------

/** States in which the API may change the version without a user action. */
export function isPollable(v: DatasetVersionOut | undefined): boolean {
  if (!v) return false;
  return (v.status === "QUARANTINED" && v.has_content) || v.status === "PROFILING";
}

export const POLL_DELAYS_MS = [1000, 2000, 4000, 8000, 15000] as const;
/** Bounded: after this many polls without a settled state, polling stops. */
export const MAX_POLLS = 60;

/**
 * The delay before the next status check, or `false` to stop. Stops for any
 * state the API will not change on its own, and after MAX_POLLS checks.
 */
export function nextPollDelay(v: DatasetVersionOut | undefined, polls: number): number | false {
  if (!isPollable(v) || polls >= MAX_POLLS) return false;
  return POLL_DELAYS_MS[Math.min(polls, POLL_DELAYS_MS.length - 1)];
}

// --- profile ----------------------------------------------------------------

const COLUMN_TYPES = new Set(["boolean", "integer", "decimal", "date", "timestamp", "string"]);
const INDICATORS = new Set([
  "possible_email",
  "possible_phone",
  "possible_national_id",
  "possible_payment_card",
  "identifier_like",
]);
const COLUMN_WARNINGS = new Set([
  "ALL_NULL",
  "TYPE_PARTIAL_PARSE",
  "FORMULA_LIKE_VALUES",
  "HEADER_NEUTRALIZED",
]);
const PROFILE_WARNINGS = new Set(["FORMULA_LIKE_CELLS", "UTF8_BOM"]);

function int(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : null;
}

function codes(v: unknown, allowed: Set<string>): string[] {
  return Array.isArray(v)
    ? v.filter((x): x is string => typeof x === "string" && allowed.has(x))
    : [];
}

/**
 * The value-free view of a profile. ONLY allowlisted structural fields are
 * kept: counts, types, sensitivity indicators and warning codes. Values the API
 * may return (minimum, maximum, mean, lengths), the content digest and any
 * field this code does not know are dropped and never rendered.
 */
export function profileView(raw: unknown): ProfileView | null {
  if (!raw || typeof raw !== "object") return null;
  const p = raw as Record<string, unknown>;
  if (p.contract_version !== "profile-2" || !Array.isArray(p.columns)) return null;
  const columns: ProfileColumnView[] = [];
  for (const c of p.columns) {
    if (!c || typeof c !== "object") return null;
    const col = c as Record<string, unknown>;
    const type = col.inferred_type;
    if (typeof col.name !== "string" || typeof col.header !== "string") return null;
    if (typeof type !== "string" || !COLUMN_TYPES.has(type)) return null;
    columns.push({
      position: int(col.position) ?? columns.length,
      header: col.header,
      name: col.name,
      inferredType: type as ProfileColumnView["inferredType"],
      nonNull: int(col.non_null_count) ?? 0,
      nulls: int(col.null_count) ?? 0,
      distinct: int(col.distinct_count),
      distinctOverLimit: col.distinct_over_limit === true,
      parseErrors: int(col.parse_error_count) ?? 0,
      formulaLike: int(col.formula_like_count) ?? 0,
      indicators: codes(col.indicators, INDICATORS),
      warnings: codes(col.warnings, COLUMN_WARNINGS),
    });
  }
  return {
    rows: int(p.row_count) ?? 0,
    columnCount: int(p.column_count) ?? columns.length,
    sizeBytes: int(p.size_bytes) ?? 0,
    encoding: p.encoding === "utf-8-sig" ? "UTF-8 (with BOM)" : "UTF-8",
    formulaLikeCells: int(p.formula_like_cells) ?? 0,
    warnings: codes(p.warnings, PROFILE_WARNINGS),
    columns,
  };
}

export const INDICATOR_LABEL: Record<string, string> = {
  possible_email: "May contain email addresses",
  possible_phone: "May contain phone numbers",
  possible_national_id: "May contain national ID numbers",
  possible_payment_card: "May contain payment card numbers",
  identifier_like: "Looks like an identifier",
};

export const WARNING_LABEL: Record<string, string> = {
  ALL_NULL: "Every value is empty",
  TYPE_PARTIAL_PARSE: "Some values do not match the detected type",
  FORMULA_LIKE_VALUES: "Some values look like spreadsheet formulas",
  HEADER_NEUTRALIZED: "The header looked like a formula and was neutralized",
  FORMULA_LIKE_CELLS: "Some cells look like spreadsheet formulas",
  UTF8_BOM: "The file starts with a byte-order mark",
};

// --- semantics (semantics-1) ------------------------------------------------

export const SEMANTIC_TYPES: SemanticType[] = [
  "category",
  "text",
  "count",
  "amount",
  "currency",
  "percentage",
  "ratio",
  "date",
  "timestamp",
  "boolean",
  "identifier",
  "contact",
];

// Mirrors nlw.datasets.semantics.COMPATIBLE_TYPES / COMPATIBLE_ROLES so the form
// offers only combinations the API accepts. The API re-validates everything.
export const COMPATIBLE_TYPES: Record<ProfileColumnView["inferredType"], SemanticType[]> = {
  integer: ["count", "amount", "currency", "percentage", "ratio", "identifier", "category"],
  decimal: ["amount", "currency", "percentage", "ratio"],
  date: ["date"],
  timestamp: ["timestamp"],
  boolean: ["boolean", "category"],
  string: ["category", "text", "identifier", "contact"],
};

export const COMPATIBLE_ROLES: Record<SemanticType, SemanticRole[]> = {
  category: ["dimension", "attribute"],
  text: ["attribute"],
  count: ["measure", "attribute"],
  amount: ["measure", "attribute"],
  currency: ["measure", "attribute"],
  percentage: ["measure", "attribute"],
  ratio: ["measure", "attribute"],
  date: ["timestamp", "dimension", "attribute"],
  timestamp: ["timestamp", "dimension", "attribute"],
  boolean: ["dimension", "attribute"],
  identifier: ["identifier"],
  contact: ["identifier", "attribute"],
};

const HARD_EXCLUDE = new Set(["possible_national_id", "possible_payment_card"]);
const IDENTIFIER_ONLY = new Set(["possible_email", "possible_phone"]);

/** A label safe to propose: the header, without characters the API refuses. */
function proposedLabel(header: string): string {
  // Control characters are removed by code point (no control-character regex).
  const visible = Array.from(header)
    .filter((ch) => {
      const cp = ch.codePointAt(0) ?? 0;
      return cp >= 0x20 && !(cp >= 0x7f && cp <= 0x9f);
    })
    .join("");
  let label = visible.replace(/\s+/g, " ").trim();
  while (label && "=+-@".includes(label[0])) label = label.slice(1).trim();
  return (label || "Column").slice(0, 80);
}

/**
 * The PROPOSED meaning of one profiled column: a starting point the admin
 * reviews and confirms (never applied automatically). Sensitive columns are
 * proposed as not analysable.
 */
export function proposeColumn(col: ProfileColumnView): SemanticColumn {
  const indicators = new Set(col.indicators);
  let semantic_type: SemanticType;
  if ([...indicators].some((i) => IDENTIFIER_ONLY.has(i))) semantic_type = "contact";
  else if (
    indicators.has("identifier_like") &&
    COMPATIBLE_TYPES[col.inferredType].includes("identifier")
  )
    semantic_type = "identifier";
  else semantic_type = COMPATIBLE_TYPES[col.inferredType][0];
  if (!COMPATIBLE_TYPES[col.inferredType].includes(semantic_type))
    semantic_type = COMPATIBLE_TYPES[col.inferredType][0];
  const role = COMPATIBLE_ROLES[semantic_type][0];
  const sensitive = [...indicators].some((i) => HARD_EXCLUDE.has(i));
  const identifierOnly = [...indicators].some((i) => IDENTIFIER_ONLY.has(i));
  return {
    name: col.name,
    label: proposedLabel(col.header),
    semantic_type,
    role,
    analysis_allowed: !sensitive && (!identifierOnly || role === "identifier"),
    description: null,
  };
}

export function proposeSemantics(profile: ProfileView): SemanticColumn[] {
  return profile.columns.map(proposeColumn);
}

/** Why a column may not be analysed, if the API would refuse it. */
export function analysisLock(col: ProfileColumnView, sem: SemanticColumn): string | null {
  if (col.indicators.some((i) => HARD_EXCLUDE.has(i)))
    return "May hold national ID or card numbers: it can never be analysed.";
  if (col.indicators.some((i) => IDENTIFIER_ONLY.has(i)) && sem.role !== "identifier")
    return "May hold contact details: analyse it only as an identifier.";
  return null;
}

// --- the file a person chooses ----------------------------------------------

export const DEFAULT_MAX_UPLOAD_BYTES = 25_000_000;

export function formatBytes(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(n % 1_000_000 === 0 ? 0 : 1)} MB`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(n % 1_000 === 0 ? 0 : 1)} KB`;
  return `${n} bytes`;
}

export type FileCheck =
  { ok: true } | { ok: false; reason: "type" | "empty" | "too_large"; message: string };

/**
 * Advisory checks before anything is sent. The API re-checks type, size and
 * content; passing here proves nothing about the file.
 */
export function checkFile(file: { name: string; size: number }, maxBytes: number): FileCheck {
  if (!/\.csv$/i.test(file.name))
    return { ok: false, reason: "type", message: "Choose a .csv file." };
  if (file.size <= 0) return { ok: false, reason: "empty", message: "That file is empty." };
  if (file.size > maxBytes) {
    // Rounded sizes can look equal (4.1 KB vs 4.1 KB): then show exact bytes.
    let size = formatBytes(file.size);
    let max = formatBytes(maxBytes);
    if (size === max) [size, max] = [`${file.size} bytes`, `${maxBytes} bytes`];
    return {
      ok: false,
      reason: "too_large",
      message: `That file is ${size}; the maximum is ${max}.`,
    };
  }
  return { ok: true };
}

// --- outcomes of initiating and uploading -----------------------------------

export type UploadOutcome =
  | "queued"
  | "not_queued"
  | "conflict"
  | "too_large"
  | "size_mismatch"
  | "malformed"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "not_enabled"
  | "rate_limited"
  | "interrupted"
  | "unknown";

export interface OutcomeCopy {
  title: string;
  detail: string;
  /** Whether trying again (with the SAME version) is safe and useful. */
  retry: boolean;
}

export const OUTCOME_COPY: Record<Exclude<UploadOutcome, "queued">, OutcomeCopy> = {
  not_queued: {
    title: "Uploaded, but processing was not queued",
    detail: "The file is stored safely. Use “Request processing again” on the version to continue.",
    retry: false,
  },
  conflict: {
    title: "This version already has a different file",
    detail: "A version keeps exactly one file. Start a new version for this file.",
    retry: false,
  },
  too_large: {
    title: "The file is too large",
    detail: "NLW refused it because it is over the upload limit.",
    retry: false,
  },
  size_mismatch: {
    title: "The file changed while it was being sent",
    detail: "Its size no longer matches. Choose the file again and start a new version.",
    retry: false,
  },
  malformed: {
    title: "The file was refused",
    detail: "It is not a CSV file NLW can accept.",
    retry: false,
  },
  unauthorized: {
    title: "Your session has ended",
    detail: "Sign in again, then come back to this dataset.",
    retry: false,
  },
  forbidden: {
    title: "You can't upload here",
    detail: "Only a workspace owner or admin can upload files.",
    retry: false,
  },
  not_found: {
    title: "That dataset or version no longer exists",
    detail: "It may have been deleted. Reload the page.",
    retry: false,
  },
  not_enabled: {
    title: "Uploads are not enabled here",
    detail: "This environment does not accept dataset uploads.",
    retry: false,
  },
  rate_limited: {
    title: "Too many requests",
    detail: "Wait a moment, then try again.",
    retry: true,
  },
  interrupted: {
    title: "The connection was interrupted",
    detail:
      "NLW may or may not have received it. Trying again is safe: it continues the " +
      "same version and never creates a second one.",
    retry: true,
  },
  unknown: {
    title: "Something went wrong",
    detail: "Trying again is safe: it continues the same version.",
    retry: true,
  },
};

const SIZE_CODES = new Set(["CONTENT_TOO_LARGE", "DATASET_SIZE_INVALID"]);
const CONFLICT_CODES = new Set([
  "CONTENT_CONFLICT",
  "DATASET_VERSION_CONFLICT",
  "IDEMPOTENCY_KEY_REUSED",
  "DATASET_NOT_ACTIVE",
]);
const MALFORMED_CODES = new Set([
  "DATASET_FILENAME_INVALID",
  "DATASET_MEDIA_TYPE_UNSUPPORTED",
  "unsupported_media_type",
]);

/**
 * Classify a failed initiation, upload or recovery request. Uses only the
 * status and the API's stable code, never the API's message text.
 */
export function classifyUploadError(error: unknown): Exclude<UploadOutcome, "queued"> {
  if (error instanceof RequestInterruptedError) return "interrupted";
  if (!(error instanceof ApiError)) return "unknown";
  if (error.code === "PROCESSING_NOT_QUEUED") return "not_queued";
  if (error.code === "CONTENT_SIZE_MISMATCH")
    return error.status === 413 ? "too_large" : "size_mismatch";
  if (SIZE_CODES.has(error.code) || error.status === 413) return "too_large";
  if (CONFLICT_CODES.has(error.code)) return "conflict";
  if (MALFORMED_CODES.has(error.code) || error.status === 415) return "malformed";
  // A missing ROUTE (generic code) means uploads are not mounted here; a
  // missing dataset or version carries its own DATASET_* code.
  if (error.status === 404) return error.code === "not_found" ? "not_enabled" : "not_found";
  switch (error.status) {
    case 401:
      return "unauthorized";
    case 403:
      return "forbidden";
    case 409:
      return "conflict";
    case 429:
      return "rate_limited";
    default:
      return "unknown";
  }
}

// --- rejection reasons ------------------------------------------------------

const REJECTION_COPY: Record<string, string> = {
  FILE_TYPE: "It is not a CSV file.",
  FILE_TOO_LARGE: "It is larger than the upload limit.",
  FILE_EMPTY: "It is empty.",
  CONTENT_BINARY: "It contains binary data, not text.",
  ENCODING_UNSUPPORTED: "It is not UTF-8 text.",
  TOO_MANY_ROWS: "It has more rows than allowed.",
  TOO_MANY_COLUMNS: "It has more columns than allowed.",
  FIELD_TOO_LARGE: "A cell is longer than allowed.",
  PARSE_TIMEOUT: "It took too long to read.",
  PARSE_ERROR: "It is not valid CSV (for example, an unclosed quote).",
  REVIEW_REJECTED: "A reviewer rejected it.",
  HEADER_INVALID: "Its header row is missing or invalid.",
  HEADER_DUPLICATE: "Two columns have the same name.",
  NO_DATA_ROWS: "It has a header but no data rows.",
  ROW_WIDTH_MISMATCH: "Some rows have a different number of columns from the header.",
  CONTENT_MISMATCH: "Its contents did not match what was uploaded.",
  PROCESSING_FAILED: "It could not be processed.",
};

export function rejectionReason(code: string | null | undefined): string {
  return (code && REJECTION_COPY[code]) || "It could not be accepted.";
}

// --- resuming an interrupted upload ------------------------------------------

/** What this browser remembers about an upload in progress for one dataset. */
export interface PendingUpload {
  key: string;
  filename: string;
  size: number;
  lastModified: number;
  versionId?: string;
}

export interface KeyValueStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

const PENDING_PREFIX = "nlw.dataset-upload.";
const NOT_QUEUED_PREFIX = "nlw.dataset-not-queued.";

function safeStore(): KeyValueStore | null {
  try {
    return typeof window !== "undefined" ? window.sessionStorage : null;
  } catch {
    return null;
  }
}

/** The stored record as a string (a stable snapshot for React to compare). */
export function pendingSnapshot(
  datasetId: string,
  store: KeyValueStore | null = safeStore(),
): string | null {
  try {
    return store?.getItem(PENDING_PREFIX + datasetId) ?? null;
  } catch {
    return null;
  }
}

export function parsePending(raw: string | null): PendingUpload | null {
  if (!raw) return null;
  try {
    const p = JSON.parse(raw) as PendingUpload;
    return typeof p.key === "string" && typeof p.filename === "string" ? p : null;
  } catch {
    return null;
  }
}

export function loadPending(
  datasetId: string,
  store: KeyValueStore | null = safeStore(),
): PendingUpload | null {
  return parsePending(pendingSnapshot(datasetId, store));
}

export function savePending(
  datasetId: string,
  pending: PendingUpload,
  store: KeyValueStore | null = safeStore(),
): void {
  store?.setItem(PENDING_PREFIX + datasetId, JSON.stringify(pending));
}

export function clearPending(datasetId: string, store: KeyValueStore | null = safeStore()): void {
  store?.removeItem(PENDING_PREFIX + datasetId);
}

export function sameFile(
  pending: PendingUpload,
  file: { name: string; size: number; lastModified: number },
): boolean {
  return (
    pending.filename === file.name &&
    pending.size === file.size &&
    pending.lastModified === file.lastModified
  );
}

/**
 * The Idempotency-Key for initiating a version of this file. A retry of the
 * SAME file reuses the remembered key, so a lost response can never create a
 * second version; a different file gets a new key.
 */
export function idempotencyKeyFor(
  datasetId: string,
  file: { name: string; size: number; lastModified: number },
  newKey: () => string,
  store: KeyValueStore | null = safeStore(),
): PendingUpload {
  const pending = loadPending(datasetId, store);
  if (pending && sameFile(pending, file)) return pending;
  const fresh: PendingUpload = {
    key: newKey(),
    filename: file.name,
    size: file.size,
    lastModified: file.lastModified,
  };
  savePending(datasetId, fresh, store);
  return fresh;
}

export function markNotQueued(
  versionId: string,
  on: boolean,
  store: KeyValueStore | null = safeStore(),
): void {
  if (on) store?.setItem(NOT_QUEUED_PREFIX + versionId, "1");
  else store?.removeItem(NOT_QUEUED_PREFIX + versionId);
}

export function isMarkedNotQueued(
  versionId: string,
  store: KeyValueStore | null = safeStore(),
): boolean {
  return store?.getItem(NOT_QUEUED_PREFIX + versionId) === "1";
}
