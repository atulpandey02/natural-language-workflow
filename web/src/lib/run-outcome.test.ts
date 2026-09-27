import { describe, expect, it } from "vitest";
import { OUTCOME_UNAVAILABLE, deriveRunOutcome } from "./run-outcome";

const base = { runStatus: "FAILED", summaryLoading: false, actionStatuses: undefined };

describe("deriveRunOutcome", () => {
  it.each(["COMPLETED", "FAILED", "FAILED_WITH_UNKNOWN", "WAITING_APPROVAL"])(
    "uses the authoritative summary outcome %s",
    (summaryOutcome) => {
      expect(deriveRunOutcome({ ...base, summaryOutcome, actionStatuses: ["failed"] })).toBe(
        summaryOutcome,
      );
    },
  );

  it("lets action evidence escalate a FAILED summary to UNKNOWN, never soften it", () => {
    expect(
      deriveRunOutcome({ ...base, summaryOutcome: "FAILED", actionStatuses: ["unknown"] }),
    ).toBe("FAILED_WITH_UNKNOWN");
    expect(
      deriveRunOutcome({ ...base, summaryOutcome: "COMPLETED", actionStatuses: ["success"] }),
    ).toBe("COMPLETED");
  });

  it("reports UNKNOWN from action evidence while the summary is loading", () => {
    expect(
      deriveRunOutcome({
        ...base,
        summaryOutcome: undefined,
        summaryLoading: true,
        actionStatuses: ["unknown"],
      }),
    ).toBe("ACTION_OUTCOME_UNKNOWN");
  });

  it("reports UNKNOWN from action evidence when the summary read failed", () => {
    expect(
      deriveRunOutcome({
        ...base,
        summaryOutcome: undefined,
        actionStatuses: ["success", "unknown"],
      }),
    ).toBe("ACTION_OUTCOME_UNKNOWN");
  });

  it("never turns a raw FAILED into a retryable failure without the summary", () => {
    for (const actionStatuses of [undefined, [], ["failed"], ["pending"]]) {
      expect(deriveRunOutcome({ ...base, summaryOutcome: undefined, actionStatuses })).toBe(
        OUTCOME_UNAVAILABLE,
      );
    }
    // While the first summary read is in flight, say nothing rather than guess.
    expect(
      deriveRunOutcome({ ...base, summaryOutcome: undefined, summaryLoading: true }),
    ).toBeUndefined();
  });

  it("passes through non-failure run states", () => {
    expect(deriveRunOutcome({ ...base, runStatus: "RUNNING", summaryOutcome: undefined })).toBe(
      "RUNNING",
    );
  });
});
