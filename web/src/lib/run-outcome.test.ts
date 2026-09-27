import { describe, expect, it } from "vitest";
import {
  OUTCOME_PENDING,
  OUTCOME_UNAVAILABLE,
  deriveRunOutcome,
  isCautiousOutcome,
  isUnknownOutcome,
} from "./run-outcome";

const read = <T>(data: T | undefined, loading = false) => ({ data, loading });

// Every outcome a summary (or raw status) could report.
const SUMMARY_OUTCOMES = [
  "COMPLETED",
  "SUCCESS",
  "PARTIAL",
  "IN_PROGRESS",
  "RUNNING",
  "PENDING",
  "WAITING_APPROVAL",
  "FAILED",
  "FAILED_WITH_UNKNOWN",
  "ACTION_OUTCOME_UNKNOWN",
  "UNKNOWN",
];

describe("deriveRunOutcome: UNKNOWN action evidence dominates", () => {
  it.each(SUMMARY_OUTCOMES)("UNKNOWN action + %s summary → UNKNOWN", (summary) => {
    const outcome = deriveRunOutcome({
      summary: read(summary),
      actions: read(["success", "unknown"]),
    });
    expect(isUnknownOutcome(outcome)).toBe(true);
    expect(isCautiousOutcome(outcome)).toBe(true);
  });

  it.each([
    ["summary loading", read<string>(undefined, true)],
    ["summary unavailable", read<string>(undefined)],
  ])("UNKNOWN action with %s → UNKNOWN", (_label, summary) => {
    expect(deriveRunOutcome({ summary, actions: read(["unknown"]) })).toBe(
      "ACTION_OUTCOME_UNKNOWN",
    );
  });
});

describe("deriveRunOutcome: no claim until the evidence is read", () => {
  it.each([
    ["summary delayed", read<string>(undefined, true), read<string[]>([])],
    ["actions delayed", read("COMPLETED"), read<string[]>(undefined, true)],
    ["both delayed", read<string>(undefined, true), read<string[]>(undefined, true)],
  ])("%s → pending", (_label, summary, actions) => {
    expect(deriveRunOutcome({ summary, actions })).toBe(OUTCOME_PENDING);
  });

  it("both evidence reads unavailable → unconfirmed, never the raw status", () => {
    expect(
      deriveRunOutcome({ summary: read<string>(undefined), actions: read<string[]>(undefined) }),
    ).toBe(OUTCOME_UNAVAILABLE);
  });

  it("summary unavailable, actions read without UNKNOWN → unconfirmed", () => {
    expect(deriveRunOutcome({ summary: read<string>(undefined), actions: read(["failed"]) })).toBe(
      OUTCOME_UNAVAILABLE,
    );
  });
});

describe("deriveRunOutcome: ordinary outcomes", () => {
  it.each(["COMPLETED", "FAILED", "PARTIAL", "WAITING_APPROVAL", "FAILED_WITH_UNKNOWN"])(
    "authoritative %s summary with consistent action evidence",
    (summary) => {
      expect(deriveRunOutcome({ summary: read(summary), actions: read(["success"]) })).toBe(
        summary,
      );
    },
  );

  it("the summary stays authoritative when only the action read failed", () => {
    expect(
      deriveRunOutcome({ summary: read("COMPLETED"), actions: read<string[]>(undefined) }),
    ).toBe("COMPLETED");
  });
});
