import { describe, expect, it } from "vitest";
import { ApiError, RequestInterruptedError } from "@/lib/errors";
import {
  DEFAULT_MAX_UPLOAD_BYTES,
  MAX_POLLS,
  POLL_DELAYS_MS,
  STATE_COPY,
  analysisLock,
  checkFile,
  classifyUploadError,
  clearPending,
  idempotencyKeyFor,
  isMarkedNotQueued,
  loadPending,
  markNotQueued,
  nextPollDelay,
  profileView,
  proposeColumn,
  rejectionReason,
  versionState,
} from "@/lib/datasets";
import { PROFILE, memoryStore, version } from "@/lib/datasets.fixtures";

describe("versionState", () => {
  it("maps every API status, with this browser's context", () => {
    expect(versionState(version())).toBe("not_uploaded");
    expect(versionState(version(), { uploading: true })).toBe("uploading");
    expect(versionState(version({ has_content: true }))).toBe("queued");
    expect(versionState(version({ has_content: true }), { notQueued: true })).toBe("not_queued");
    expect(versionState(version({ status: "PROFILING", has_content: true }))).toBe("processing");
    expect(versionState(version({ status: "PROFILED" }))).toBe("awaiting_semantics");
    expect(versionState(version({ status: "PROFILED" }), { semanticRevisions: 1 })).toBe(
      "ready_to_activate",
    );
    expect(versionState(version({ status: "ACTIVE" }))).toBe("active");
    expect(versionState(version({ status: "SUPERSEDED" }))).toBe("superseded");
    expect(versionState(version({ status: "REJECTED" }))).toBe("rejected");
    expect(versionState(version({ status: "DELETING" }))).toBe("deleting");
  });

  it("never describes a deletion request as a physical purge", () => {
    const copy = STATE_COPY.deleting;
    expect(copy.label).toBe("Deletion requested");
    expect(`${copy.label} ${copy.detail}`).not.toMatch(/\bpurged\b|\bremoved\b(?! separately)/i);
    expect(copy.detail).toMatch(/does not confirm that removal/);
  });
});

describe("polling", () => {
  it("polls only while the API may still change the version, with backoff", () => {
    const queued = version({ has_content: true });
    expect(nextPollDelay(queued, 0)).toBe(POLL_DELAYS_MS[0]);
    expect(nextPollDelay(queued, 1)).toBe(POLL_DELAYS_MS[1]);
    expect(nextPollDelay(queued, 50)).toBe(POLL_DELAYS_MS[POLL_DELAYS_MS.length - 1]);
    expect(nextPollDelay(version({ status: "PROFILING", has_content: true }), 3)).toBe(8000);
  });

  it.each(["PROFILED", "ACTIVE", "SUPERSEDED", "REJECTED", "DELETING"] as const)(
    "stops for the terminal state %s",
    (status) => {
      expect(nextPollDelay(version({ status, has_content: true }), 0)).toBe(false);
    },
  );

  it("does not poll a version waiting for its file, or an unknown one", () => {
    expect(nextPollDelay(version(), 0)).toBe(false);
    expect(nextPollDelay(undefined, 0)).toBe(false);
  });

  it("is bounded: it stops after MAX_POLLS checks", () => {
    expect(nextPollDelay(version({ has_content: true }), MAX_POLLS - 1)).not.toBe(false);
    expect(nextPollDelay(version({ has_content: true }), MAX_POLLS)).toBe(false);
  });
});

describe("profileView", () => {
  it("keeps only counts, types, indicators and known codes", () => {
    const view = profileView(PROFILE)!;
    expect(view.rows).toBe(3);
    expect(view.warnings).toEqual(["UTF8_BOM"]);
    expect(view.columns.map((c) => c.inferredType)).toEqual(["string", "decimal", "string"]);
    expect(view.columns[2].indicators).toEqual(["possible_email"]);
    expect(view.columns[2].warnings).toEqual([]);
    const text = JSON.stringify(view);
    for (const leaked of [
      "SENTINEL-MIN-901",
      "SENTINEL-MAX-902",
      "903.25",
      "source.csv",
      "a".repeat(64),
    ])
      expect(text).not.toContain(leaked);
    for (const field of [
      "min_value",
      "max_value",
      "mean",
      "min_length",
      "content_sha256",
      "storage_key",
    ])
      expect(text).not.toContain(field);
  });

  it("refuses anything that is not a profile-2 document", () => {
    expect(profileView(null)).toBeNull();
    expect(profileView({ contract_version: "profile-1", columns: [] })).toBeNull();
    expect(
      profileView({ ...PROFILE, columns: [{ name: "x", header: "X", inferred_type: "blob" }] }),
    ).toBeNull();
  });
});

describe("proposed semantics", () => {
  const view = profileView(PROFILE)!;

  it("proposes a compatible type and role for each column", () => {
    expect(proposeColumn(view.columns[0])).toMatchObject({
      name: "region",
      label: "Region",
      semantic_type: "category",
      role: "dimension",
      analysis_allowed: true,
    });
    expect(proposeColumn(view.columns[1])).toMatchObject({
      semantic_type: "amount",
      role: "measure",
    });
  });

  it("proposes sensitive columns as identifiers, or not analysable", () => {
    const email = proposeColumn(view.columns[2]);
    expect(email).toMatchObject({
      semantic_type: "contact",
      role: "identifier",
      analysis_allowed: true,
    });
    const card = { ...view.columns[0], indicators: ["possible_payment_card"] };
    expect(proposeColumn(card).analysis_allowed).toBe(false);
    expect(analysisLock(card, proposeColumn(card))).toMatch(/never be analysed/);
  });

  it("never proposes a label the API would refuse", () => {
    const col = { ...view.columns[0], header: "=SUM(A1)\u0007 total" };
    expect(proposeColumn(col).label).toBe("SUM(A1) total");
  });
});

describe("checkFile (advisory)", () => {
  it("accepts a .csv within the limit", () => {
    expect(checkFile({ name: "Orders.CSV", size: 10 }, 100)).toEqual({ ok: true });
  });
  it.each([
    [{ name: "orders.xlsx", size: 10 }, "type"],
    [{ name: "orders.csv.exe", size: 10 }, "type"],
    [{ name: "orders.csv", size: 0 }, "empty"],
    [{ name: "orders.csv", size: 101 }, "too_large"],
  ])("refuses %o (%s)", (file, reason) => {
    const r = checkFile(file, 100);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe(reason);
  });
  it("states the configured maximum", () => {
    const r = checkFile(
      { name: "big.csv", size: DEFAULT_MAX_UPLOAD_BYTES + 1 },
      DEFAULT_MAX_UPLOAD_BYTES,
    );
    expect(r.ok === false && r.message).toContain("the maximum is 25 MB");
  });
  it("uses exact bytes when the rounded sizes would look equal", () => {
    const r = checkFile({ name: "big.csv", size: 4098 }, 4096);
    expect(r.ok === false && r.message).toBe("That file is 4098 bytes; the maximum is 4096 bytes.");
  });
});

describe("classifyUploadError", () => {
  const api = (status: number, code: string) =>
    new ApiError({ status, code, message: "raw detail" });
  it.each([
    [api(503, "PROCESSING_NOT_QUEUED"), "not_queued"],
    [api(409, "CONTENT_CONFLICT"), "conflict"],
    [api(409, "IDEMPOTENCY_KEY_REUSED"), "conflict"],
    [api(413, "CONTENT_TOO_LARGE"), "too_large"],
    [api(413, "CONTENT_SIZE_MISMATCH"), "too_large"],
    [api(422, "CONTENT_SIZE_MISMATCH"), "size_mismatch"],
    [api(422, "DATASET_FILENAME_INVALID"), "malformed"],
    [api(401, "unauthorized"), "unauthorized"],
    [api(403, "forbidden"), "forbidden"],
    [api(404, "not_found"), "not_enabled"],
    [api(404, "DATASET_VERSION_NOT_FOUND"), "not_found"],
    [api(429, "rate_limited"), "rate_limited"],
    [api(500, "internal_error"), "unknown"],
    [new RequestInterruptedError("PUT"), "interrupted"],
    [new Error("boom"), "unknown"],
  ])("%o -> %s", (error, outcome) => {
    expect(classifyUploadError(error)).toBe(outcome);
  });

  it("maps rejection codes to plain reasons, never raw text", () => {
    expect(rejectionReason("ROW_WIDTH_MISMATCH")).toMatch(/different number of columns/);
    expect(rejectionReason("SOMETHING_ELSE")).toBe("It could not be accepted.");
    expect(rejectionReason(null)).toBe("It could not be accepted.");
  });
});

describe("idempotency keys", () => {
  const file = { name: "orders.csv", size: 120, lastModified: 1 };

  it("reuses the key for a retry of the same file", () => {
    const store = memoryStore();
    let n = 0;
    const mk = () => `key-${++n}`;
    const first = idempotencyKeyFor("d1", file, mk, store);
    const again = idempotencyKeyFor("d1", { ...file }, mk, store);
    expect(again.key).toBe(first.key);
    expect(n).toBe(1);
  });

  it("uses a new key for a different file or after the upload finished", () => {
    const store = memoryStore();
    let n = 0;
    const mk = () => `key-${++n}`;
    const first = idempotencyKeyFor("d1", file, mk, store);
    const other = idempotencyKeyFor("d1", { ...file, lastModified: 2 }, mk, store);
    expect(other.key).not.toBe(first.key);
    clearPending("d1", store);
    expect(loadPending("d1", store)).toBeNull();
    expect(idempotencyKeyFor("d1", file, mk, store).key).toBe("key-3");
  });

  it("keeps keys per dataset", () => {
    const store = memoryStore();
    let n = 0;
    const mk = () => `key-${++n}`;
    expect(idempotencyKeyFor("d1", file, mk, store).key).not.toBe(
      idempotencyKeyFor("d2", file, mk, store).key,
    );
  });

  it("remembers a not-queued version across a reload, and forgets it", () => {
    const store = memoryStore();
    markNotQueued("v1", true, store);
    expect(isMarkedNotQueued("v1", store)).toBe(true);
    markNotQueued("v1", false, store);
    expect(isMarkedNotQueued("v1", store)).toBe(false);
  });
});
