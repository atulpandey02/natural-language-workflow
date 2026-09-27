import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ApiError } from "@/lib/errors";
import { ErrorBanner, OutcomeNotice } from "@/components/ui";
import {
  RETRY_TEXT,
  UserFacingError,
  describeAuthError,
  describeError,
  describeOutcome,
} from "./friendly-errors";

const api = (status: number, code: string, message: string, extra: object = {}) =>
  new ApiError({ status, code, message, ...extra });

describe("describeError: every expected failure class has friendly copy", () => {
  it.each([
    [
      api(400, "bad_request", "X-Workspace-Id must be a UUID"),
      "bad_request",
      "That request couldn't be processed",
    ],
    [api(401, "unauthorized", "Not authenticated."), "unauthorized", "Your session has ended"],
    [api(403, "forbidden", "insufficient role"), "forbidden", "You don't have access to that"],
    [api(404, "not_found", "workflow not found"), "not_found", "We couldn't find that"],
    [
      api(409, "conflict", "some new conflict"),
      "conflict",
      "That conflicts with the current state",
    ],
    [
      api(422, "validation_error", "request validation failed"),
      "validation",
      "Some details need attention",
    ],
    [api(429, "rate_limited", "rate limit exceeded"), "rate_limited", "Too many requests"],
    [
      api(503, "service_unavailable", "signed database context unavailable"),
      "unavailable",
      "Temporarily unavailable",
    ],
    [
      api(500, "internal_error", "internal server error"),
      "server",
      "Something went wrong on our side",
    ],
    [new TypeError("Failed to fetch"), "network", "Can't reach NLW"],
    [new Error("anything"), "unexpected", "Something went wrong"],
  ])("%#: %s -> %s", (error, kind, title) => {
    const f = describeError(error);
    expect(f?.kind).toBe(kind);
    expect(f?.title).toBe(title);
    expect(f?.action.length).toBeGreaterThan(10);
  });

  it("maps stable backend codes and messages to purpose-written copy", () => {
    const stale = describeError(
      api(409, "STALE_PLAN", "connector changed: CONNECTOR_CONFIG_CHANGED"),
    );
    expect(stale?.title).toBe("This plan is out of date");
    expect(stale?.retry).toBe("no");
    expect(
      describeError(api(503, "service_unavailable", "planner provider unavailable"))?.title,
    ).toBe("The planner is unavailable");
    expect(
      describeError(api(403, "forbidden", "you cannot decide an approval you requested"))?.title,
    ).toBe("Someone else must approve this");
    expect(
      describeError(api(409, "conflict", "a pending invitation for this email already exists"))
        ?.title,
    ).toBe("Already invited");
    expect(
      describeError(api(409, "conflict", "removal not allowed (workspace must keep an owner)"))
        ?.title,
    ).toBe("A workspace needs an owner");
  });

  it("points at fields from 422 details without echoing validator text", () => {
    const f = describeError(
      api(422, "validation_error", "request validation failed", {
        details: [
          {
            loc: ["body", "config", "default_channel"],
            msg: "Value error, must match ^[CGD]",
            type: "value_error",
          },
          { loc: ["body", "name"], msg: "Field required", type: "missing" },
        ],
      }),
    );
    expect(f?.fields).toEqual({
      "config.default_channel": "This value isn't accepted.",
      name: "This field is required.",
    });
    expect(JSON.stringify(f)).not.toMatch(/Value error|\^\[CGD\]|Field required/);
  });

  it("shows only a sanitized, id-shaped reference", () => {
    expect(
      describeError(api(500, "internal_error", "x", { requestId: "5f2c9a1e-8b7d-4c3a" }))
        ?.reference,
    ).toBe("5f2c9a1e-8b7");
    expect(
      describeError(api(500, "internal_error", "x", { requestId: "<script>alert(1)</script>" }))
        ?.reference,
    ).toBeUndefined();
  });

  it("renders app-authored UserFacingError copy verbatim and nothing else", () => {
    const f = describeError(
      new UserFacingError("x", {
        title: "T",
        explanation: "E",
        action: "A",
        retry: "now",
        tone: "warn",
      }),
    );
    expect(f).toMatchObject({ kind: "x", title: "T", explanation: "E", action: "A" });
  });
});

describe("workflow outcomes", () => {
  it("never suggests a blind retry for an UNKNOWN external action", () => {
    for (const outcome of ["FAILED_WITH_UNKNOWN", "ACTION_OUTCOME_UNKNOWN", "UNKNOWN"]) {
      const f = describeOutcome(outcome);
      expect(f?.retry).toBe("no");
      expect(f?.title).toBe("We can't confirm whether the action happened");
      expect(f?.action).toMatch(/Don't simply run it again/);
      expect(`${f?.action} ${RETRY_TEXT[f!.retry]}`).not.toMatch(/try again now/i);
    }
  });

  it("explains failed and partial runs; completed needs no notice", () => {
    expect(describeOutcome("FAILED")?.title).toBe("This run didn't finish");
    expect(describeOutcome("PARTIAL")?.explanation).toMatch(/can't be shared/);
    expect(describeOutcome("COMPLETED")).toBeNull();
    expect(describeOutcome(undefined)).toBeNull();
  });
});

describe("ErrorBanner never renders raw provider/API/Pydantic/SQL text", () => {
  const RAW = [
    "1 validation error for SlackConnectorConfig\nworkspace_label\n  Field required [type=missing] For further information visit https://errors.pydantic.dev/2.9/v/missing",
    'duplicate key value violates unique constraint "uq_invitation_pending_email"',
    "psycopg.errors.InsufficientPrivilege: permission denied for table memberships",
    'Traceback (most recent call last):\n  File "/app/nlw/api.py", line 1',
    '{"detail":[{"loc":["body"],"msg":"Field required"}]}',
    "tenant 9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d not found",
  ];
  it.each(RAW)("hides: %s", (raw) => {
    for (const error of [
      api(422, "unprocessable_entity", raw),
      api(500, "internal_error", raw),
      new Error(raw),
    ]) {
      const { unmount } = render(<ErrorBanner error={error} />);
      const text = screen.getByTestId("friendly-error").textContent ?? "";
      expect(text).not.toContain(raw.slice(0, 20));
      expect(text).not.toMatch(
        /pydantic|psycopg|Traceback|uq_|\{"detail"|[0-9a-f]{8}-[0-9a-f]{4}-/i,
      );
      unmount();
    }
  });

  it("renders title, explanation, next step and retry guidance with alert semantics", () => {
    render(<ErrorBanner error={api(429, "rate_limited", "slow down")} />);
    const panel = screen.getByRole("alert");
    expect(panel).toHaveTextContent("Too many requests");
    expect(panel).toHaveTextContent("Wait a minute, then try again.");
    expect(panel).toHaveTextContent(RETRY_TEXT.later);
  });

  it("uses a polite status region for outcome notices", () => {
    render(<OutcomeNotice outcome="FAILED_WITH_UNKNOWN" />);
    expect(screen.getByRole("status")).toHaveTextContent(
      "We can't confirm whether the action happened",
    );
  });
});

describe("describeAuthError", () => {
  it("never echoes the provider message", () => {
    expect(describeAuthError({ status: 400, message: "Invalid login credentials" })?.title).toBe(
      "Email or password is incorrect",
    );
    expect(describeAuthError({ status: 429, message: "Request rate limit reached" })?.title).toBe(
      "Too many sign-in attempts",
    );
    const other = describeAuthError({
      status: 500,
      message: "AuthRetryableFetchError: gotrue 10.0.0.1",
    });
    expect(JSON.stringify(other)).not.toMatch(/gotrue|10\.0\.0\.1|AuthRetryable/);
    expect(describeAuthError(null)).toBeNull();
  });
});

describe("analysis journey copy", () => {
  it("explains a version without a recorded request instead of echoing the API", () => {
    const f = describeError(api(404, "not_found", "no provenance for this version"));
    expect(f?.title).toBe("No original request on record");
    expect(JSON.stringify(f)).not.toContain("no provenance");
  });
});

describe("every state says whether anything changed", () => {
  it("reads and rejected requests changed nothing; server errors say to check", () => {
    expect(describeError(api(404, "not_found", "x"))?.changed).toBe("Nothing was changed.");
    expect(describeError(api(422, "validation_error", "x"))?.changed).toBe("Nothing was changed.");
    expect(describeError(new TypeError("Failed to fetch"))?.changed).toBe("Nothing was changed.");
    expect(describeError(api(500, "internal_error", "x"))?.changed).toMatch(/check whether/);
  });

  it("outcomes state what ran; UNKNOWN is explicitly not a success", () => {
    expect(describeOutcome("FAILED")?.changed).toMatch(/Completed steps .* kept/);
    expect(describeOutcome("PARTIAL")?.changed).toMatch(/Nothing was shared/);
    expect(describeOutcome("FAILED_WITH_UNKNOWN")?.changed).toBe(
      "The external action may have happened. This is not a success.",
    );
  });

  it("renders the changed line in the panel", () => {
    render(<ErrorBanner error={api(403, "forbidden", "insufficient role")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Nothing was changed.");
  });
});
