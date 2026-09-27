import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ApiError, RequestInterruptedError } from "@/lib/errors";
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
    [new TypeError("Failed to fetch"), "interrupted", "We couldn't confirm the result"],
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

describe("mutation state: never claim nothing changed unless it's proven", () => {
  const write = (status: number, code: string, message: string) =>
    new ApiError({ status, code, message, method: "POST" });
  const UNCONFIRMED = "We couldn't confirm whether your change was saved.";

  it.each([
    ["TypeError", new TypeError("Failed to fetch")],
    ["AbortError", Object.assign(new Error("aborted"), { name: "AbortError" })],
    ["interrupted write", new RequestInterruptedError("POST")],
  ])("%s is an unknown outcome with check-before-retry guidance", (_n, error) => {
    const f = describeError(error)!;
    expect(f.mutation).toBe("unknown");
    expect(f.changed).toBe(UNCONFIRMED);
    expect(f.retry).toBe("no");
    expect(f.action).toMatch(/check the relevant list or record before trying again/);
    expect(JSON.stringify(f)).not.toContain("Nothing was changed");
  });

  it.each([502, 503, 504, 500])(
    "an ambiguous %i on a write is unknown, never 'nothing changed'",
    (status) => {
      const f = describeError(write(status, "service_unavailable", "upstream"))!;
      expect(f.mutation).toBe("unknown");
      expect(f.changed).toBe(UNCONFIRMED);
      expect(f.retry).toBe("no");
      expect(`${f.action} ${RETRY_TEXT[f.retry]}`).not.toMatch(/try again now/i);
    },
  );

  it("a definite validation rejection changed nothing", () => {
    const f = describeError(write(422, "validation_error", "request validation failed"))!;
    expect(f.mutation).toBe("unchanged");
    expect(f.changed).toBe("Nothing was changed.");
  });

  it("an authorization denial changed nothing", () => {
    expect(describeError(write(403, "forbidden", "insufficient role"))?.changed).toBe(
      "Nothing was changed.",
    );
  });

  it("the approval enqueue failure says the decision was saved, and nothing else", () => {
    const f = describeError(
      write(503, "service_unavailable", "decision saved but resume could not be scheduled"),
    )!;
    expect(f.mutation).toBe("changed");
    expect(f.changed).toBe(
      "Your decision was saved. Scheduling the run to continue did not complete.",
    );
    expect(f.retry).toBe("no");
    expect(JSON.stringify(f)).not.toMatch(/Nothing was changed|couldn't confirm/);
  });

  it("reads make no claim about changes and keep ordinary retry guidance", () => {
    const read = new ApiError({
      status: 503,
      code: "service_unavailable",
      message: "x",
      method: "GET",
    });
    const f = describeError(read)!;
    expect(f.mutation).toBeUndefined();
    expect(f.changed).toBeUndefined();
    expect(describeError(new RequestInterruptedError("GET"))?.kind).toBe("network");
  });

  it("outcomes state what ran; UNKNOWN is explicitly not a success", () => {
    expect(describeOutcome("FAILED")?.changed).toMatch(/Completed steps .* kept/);
    expect(describeOutcome("PARTIAL")?.changed).toMatch(/completed steps ran/);
    expect(describeOutcome("FAILED_WITH_UNKNOWN")?.changed).toBe(
      "The external action may have happened. This is not a success.",
    );
    const unavailable = describeOutcome("OUTCOME_UNAVAILABLE")!;
    expect(unavailable.retry).toBe("no");
    expect(unavailable.changed).toMatch(/may have run/);
    expect(JSON.stringify(unavailable)).not.toMatch(/Nothing was changed|try again now/i);
  });

  it("renders the mutation line in the panel", () => {
    render(<ErrorBanner error={write(403, "forbidden", "insufficient role")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Nothing was changed.");
  });
});

describe("fully composed banners never contradict the mutation state (B2)", () => {
  const banner = (status: number, method: string, message = "internal server error") => {
    const { unmount } = render(
      <ErrorBanner
        error={
          new ApiError({ status, code: status >= 500 ? "internal_error" : "x", message, method })
        }
      />,
    );
    const text = screen.getByTestId("friendly-error").textContent ?? "";
    unmount();
    return text;
  };
  const UNSAFE = [
    /safe to try again/i,
    /request didn.t complete/i,
    /nothing was changed/i,
    /try again now/i,
  ];

  it.each([
    [500, "POST"],
    [500, "PATCH"],
    [500, "PUT"],
    [500, "DELETE"],
    [502, "POST"],
    [503, "POST"],
    [504, "POST"],
    [503, "DELETE"],
  ])("write-side %i %s: unconfirmed, check first, no safe-retry claim", (status, method) => {
    const text = banner(status, method);
    for (const unsafe of UNSAFE) expect(text).not.toMatch(unsafe);
    expect(text).toContain("We couldn't confirm whether your change was saved.");
    expect(text).toContain("check the relevant list or record before trying again");
    expect(text).toContain("Don't repeat it until you've checked.");
  });

  it("GET 500 offers to load again, clearly as a read", () => {
    const text = banner(500, "GET");
    expect(text).toContain("Try loading it again.");
    expect(text).toMatch(/try loading it again/i);
    for (const unsafe of UNSAFE) expect(text).not.toMatch(unsafe);
    expect(text).not.toMatch(/couldn't confirm whether your change/);
  });

  it("approval enqueue failure: decision saved, continuation not scheduled", () => {
    const text = banner(503, "POST", "decision saved but resume could not be scheduled");
    expect(text).toContain(
      "Your decision was saved. Scheduling the run to continue did not complete.",
    );
    for (const unsafe of UNSAFE) expect(text).not.toMatch(unsafe);
    expect(text).not.toMatch(/couldn't confirm/);
  });

  it("run created but not scheduled is reported as saved, not retryable", () => {
    const text = banner(
      503,
      "POST",
      "run created but could not be scheduled; it will be recovered automatically",
    );
    expect(text).toContain("The run was created.");
    expect(text).toContain("Don't start it again.");
    for (const unsafe of UNSAFE) expect(text).not.toMatch(unsafe);
  });

  it("a known-unchanged planner outage keeps its own guidance", () => {
    const text = banner(503, "POST", "planner provider unavailable");
    expect(text).toContain("The planner is unavailable");
    expect(text).toContain("Nothing was changed.");
    expect(text).not.toMatch(/couldn't confirm/);
  });

  it("a validation rejection still says nothing was changed", () => {
    const { unmount } = render(
      <ErrorBanner
        error={
          new ApiError({
            status: 422,
            code: "validation_error",
            message: "request validation failed",
            method: "POST",
          })
        }
      />,
    );
    expect(screen.getByTestId("friendly-error")).toHaveTextContent("Nothing was changed.");
    unmount();
  });
});
