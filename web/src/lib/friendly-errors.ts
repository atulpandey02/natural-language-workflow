// Centralized, user-facing error language. Every page renders errors through
// describeError(): a short title, a plain-language explanation, a safe next
// action and retry guidance — never raw provider/API/Pydantic/SQL text, internal
// identifiers or stack traces. Only a sanitized request reference is shown.
import { ApiError } from "@/lib/errors";

export type Tone = "error" | "warn" | "info";
/** now = safe to retry immediately; later = wait first; no = do not blindly retry. */
export type Retry = "now" | "later" | "no";

export interface FriendlyError {
  title: string;
  explanation: string;
  action: string;
  retry: Retry;
  tone: Tone;
  reference?: string;
  /** Friendly per-field messages from a 422 validation response (field -> text). */
  fields?: Record<string, string>;
  /** Stable machine class, for tests and analytics (never shown). */
  kind: string;
}

type Copy = Omit<FriendlyError, "reference" | "fields" | "kind">;

/**
 * An error whose copy is written by this app for users (never a provider/API
 * string). Only these, and mapped API errors, render specific text; any other
 * thrown value gets the generic safe message.
 */
export class UserFacingError extends Error {
  readonly copy: Copy;
  readonly kind: string;
  constructor(kind: string, copy: Copy) {
    super(copy.title);
    this.name = "UserFacingError";
    this.kind = kind;
    this.copy = copy;
  }
}

const GENERIC: Record<string, Copy> = {
  network: {
    title: "Can't reach NLW",
    explanation: "Your browser couldn't connect. Nothing was changed.",
    action: "Check your connection, then try again.",
    retry: "now",
    tone: "error",
  },
  bad_request: {
    title: "That request couldn't be processed",
    explanation: "Something about the request wasn't in the expected form.",
    action: "Check what you entered and try again.",
    retry: "now",
    tone: "error",
  },
  unauthorized: {
    title: "Your session has ended",
    explanation: "For your security, you've been signed out.",
    action: "Sign in again to continue.",
    retry: "no",
    tone: "warn",
  },
  forbidden: {
    title: "You don't have access to that",
    explanation: "Your role in this workspace doesn't allow this action.",
    action: "Ask a workspace owner or admin if you need access.",
    retry: "no",
    tone: "warn",
  },
  not_found: {
    title: "We couldn't find that",
    explanation: "It may have been removed, or it isn't part of the workspace you're using.",
    action: "Go back and choose it again, or switch workspace.",
    retry: "no",
    tone: "warn",
  },
  conflict: {
    title: "That conflicts with the current state",
    explanation: "Something changed since this page loaded.",
    action: "Refresh the page and try again.",
    retry: "now",
    tone: "warn",
  },
  validation: {
    title: "Some details need attention",
    explanation: "A few values weren't accepted.",
    action: "Fix the highlighted fields and submit again.",
    retry: "now",
    tone: "warn",
  },
  rate_limited: {
    title: "Too many requests",
    explanation: "You're going faster than this pilot allows.",
    action: "Wait a minute, then try again.",
    retry: "later",
    tone: "warn",
  },
  unavailable: {
    title: "Temporarily unavailable",
    explanation: "A service NLW depends on isn't responding right now. Nothing was changed.",
    action: "Try again in a minute.",
    retry: "later",
    tone: "warn",
  },
  server: {
    title: "Something went wrong on our side",
    explanation: "The request didn't complete. It's safe to try again.",
    action: "Try again. If it keeps happening, share the reference with your administrator.",
    retry: "now",
    tone: "error",
  },
  unexpected: {
    title: "Something went wrong",
    explanation: "An unexpected problem stopped this action.",
    action: "Refresh the page and try again.",
    retry: "now",
    tone: "error",
  },
};

// Stable, author-controlled backend codes/messages -> purpose-written copy.
const KNOWN: Record<string, Copy> = {
  STALE_PLAN: {
    title: "This plan is out of date",
    explanation:
      "A connector or tool it relies on changed after it was planned, so it can't run as-is.",
    action: "Ask your question again to get a fresh plan.",
    retry: "no",
    tone: "warn",
  },
  STALE_ANALYTICS_SOURCE: {
    title: "The analysis behind this summary changed",
    explanation: "The Slack summary no longer matches its source analysis, so it was not sent.",
    action: "Open the analysis and create a new share proposal.",
    retry: "no",
    tone: "warn",
  },
  INVALID_PLAN: {
    title: "This plan can't run",
    explanation: "The plan didn't pass NLW's safety and feasibility checks.",
    action: "Rephrase your question and prepare the plan again.",
    retry: "no",
    tone: "warn",
  },
  SCHEDULE_CREATOR_UNAUTHORIZED: {
    title: "The schedule's creator no longer has access",
    explanation: "Scheduled work only runs for someone who is still an owner or admin here.",
    action: "Restore their role, or recreate the schedule yourself.",
    retry: "no",
    tone: "warn",
  },
  "planner provider unavailable": {
    title: "The planner is unavailable",
    explanation: "NLW couldn't reach its planning service. Your question wasn't lost.",
    action: "Try again in a minute.",
    retry: "later",
    tone: "warn",
  },
  "planner provider misconfigured": {
    title: "The planner isn't set up",
    explanation: "This environment's planning service isn't configured.",
    action: "Contact your administrator.",
    retry: "no",
    tone: "error",
  },
  "you cannot decide an approval you requested": {
    title: "Someone else must approve this",
    explanation: "Approvals need a second person, so you can't approve or reject your own request.",
    action: "Ask another owner or admin in this workspace to review it.",
    retry: "no",
    tone: "info",
  },
  "approval already decided": {
    title: "Already decided",
    explanation: "Someone has already approved or rejected this request.",
    action: "Refresh to see the decision.",
    retry: "no",
    tone: "info",
  },
  "a pending invitation for this email already exists": {
    title: "Already invited",
    explanation: "There's already a pending invitation for that email address.",
    action: "Revoke the pending invitation first, or wait for them to accept it.",
    retry: "no",
    tone: "info",
  },
  "too many pending invitations for this workspace": {
    title: "Too many pending invitations",
    explanation: "This workspace has reached its limit of open invitations.",
    action: "Revoke invitations that are no longer needed, then try again.",
    retry: "no",
    tone: "warn",
  },
  "invitation is not valid": {
    title: "This invitation is not valid",
    explanation:
      "Invitations work once, only for the invited email address, and expire after a few days.",
    action: "Ask the workspace owner or an admin for a new invitation.",
    retry: "no",
    tone: "warn",
  },
  "decision saved but resume could not be scheduled": {
    title: "Decision saved — the run will continue shortly",
    explanation: "Your decision was recorded, but the run couldn't be resumed right away.",
    action: "Check the run in a minute. Don't decide again.",
    retry: "no",
    tone: "info",
  },
  "workflow has no materialized version to run": {
    title: "This workflow isn't ready to run",
    explanation: "It has no confirmed version yet.",
    action: "Prepare a plan, review it and choose Save workflow first.",
    retry: "no",
    tone: "warn",
  },
  "no provenance for this version": {
    title: "No original request on record",
    explanation:
      "This workflow version was created without a recorded question, so there is nothing to show here.",
    action: "You can still run it; results link to the steps that produced them.",
    retry: "no",
    tone: "info",
  },
  "proposal has no materializable plan": {
    title: "This plan can't become a workflow",
    explanation: "It needs clarification or was rejected by the safety checks.",
    action: "Rephrase your question and prepare the plan again.",
    retry: "no",
    tone: "warn",
  },
  "workspace must keep an owner": {
    title: "A workspace needs an owner",
    explanation: "This change would leave the workspace without any owner.",
    action: "Make someone else an owner first.",
    retry: "no",
    tone: "warn",
  },
};

// Friendly text per Pydantic error `type` (the message itself is never shown).
const FIELD_TYPE: Record<string, string> = {
  missing: "This field is required.",
  string_too_short: "This is too short.",
  string_too_long: "This is too long.",
  string_pattern_mismatch: "This isn't in the expected format.",
  value_error: "This value isn't accepted.",
  int_parsing: "Enter a whole number.",
  extra_forbidden: "This field isn't supported.",
};

function toKind(status: number): string {
  if (status === 0) return "network";
  if (status === 400) return "bad_request";
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 422) return "validation";
  if (status === 429) return "rate_limited";
  if (status === 502 || status === 503 || status === 504) return "unavailable";
  if (status >= 500) return "server";
  return "unexpected";
}

/** A safe request reference: short, id-shaped, never free text. */
function safeReference(id: string | undefined): string | undefined {
  return id && /^[A-Za-z0-9-]{6,64}$/.test(id) ? id.slice(0, 12) : undefined;
}

function fieldErrors(details: unknown): Record<string, string> | undefined {
  if (!Array.isArray(details)) return undefined;
  const out: Record<string, string> = {};
  for (const d of details) {
    if (!d || typeof d !== "object") continue;
    const loc = (d as { loc?: unknown }).loc;
    const type = String((d as { type?: unknown }).type ?? "");
    if (!Array.isArray(loc)) continue;
    const field = loc.filter((p) => p !== "body" && typeof p === "string").join(".");
    if (field && !(field in out)) out[field] = FIELD_TYPE[type] ?? "This value isn't accepted.";
  }
  return Object.keys(out).length ? out : undefined;
}

function isNetworkError(error: unknown): boolean {
  return error instanceof TypeError || (error instanceof Error && error.name === "AbortError");
}

export function describeError(error: unknown): FriendlyError | null {
  if (!error) return null;
  if (error instanceof ApiError) {
    const lastOwner =
      error.status === 409 && error.message.endsWith("(workspace must keep an owner)");
    const known =
      KNOWN[error.code] ??
      KNOWN[error.message] ??
      (lastOwner ? KNOWN["workspace must keep an owner"] : undefined);
    const kind = known ? (KNOWN[error.code] ? error.code : "known") : toKind(error.status);
    const copy = known ?? GENERIC[kind] ?? GENERIC.unexpected;
    return {
      ...copy,
      kind,
      reference: safeReference(error.requestId),
      fields: error.status === 422 ? fieldErrors(error.details) : undefined,
    };
  }
  if (error instanceof UserFacingError) return { ...error.copy, kind: error.kind };
  if (isNetworkError(error)) return { ...GENERIC.network, kind: "network" };
  return { ...GENERIC.unexpected, kind: "unexpected" };
}

// ---- workflow outcomes (not HTTP errors, but the same language) --------------
export function describeOutcome(outcome: string | undefined): FriendlyError | null {
  switch (outcome) {
    case "FAILED":
      return {
        kind: "run_failed",
        title: "This run didn't finish",
        explanation: "A step failed, so later steps were skipped. Completed results are kept.",
        action: "Review the failed step below. You can run the workflow again when ready.",
        retry: "now",
        tone: "error",
      };
    case "PARTIAL":
      return {
        kind: "run_partial",
        title: "Partial results",
        explanation:
          "Some steps completed and others did not. Only verified results are shown and they can't be shared.",
        action: "Review which steps failed before relying on these results.",
        retry: "now",
        tone: "warn",
      };
    case "FAILED_WITH_UNKNOWN":
    case "ACTION_OUTCOME_UNKNOWN":
    case "UNKNOWN":
      return {
        kind: "outcome_unknown",
        title: "We can't confirm whether the action happened",
        explanation:
          "The external system didn't give a clear answer. The action may or may not have taken effect, so NLW did not retry it.",
        action:
          "Check the destination (for example, the Slack channel) first. Don't simply run it again — that could send a duplicate.",
        retry: "no",
        tone: "warn",
      };
    default:
      return null;
  }
}

export const RETRY_TEXT: Record<Retry, string> = {
  now: "You can try again now.",
  later: "Wait a little before trying again.",
  no: "Don't retry blindly.",
};

// ---- sign-in (Supabase Auth) --------------------------------------------------
/** Friendly copy for a password sign-in failure. Never echoes the provider text. */
export function describeAuthError(error: { status?: number; message?: string } | null) {
  if (!error) return null;
  const msg = (error.message ?? "").toLowerCase();
  if (msg.includes("invalid login credentials") || error.status === 400) {
    return {
      title: "Email or password is incorrect",
      explanation: "Check both and try again. Access is by invitation only.",
    };
  }
  if (msg.includes("email not confirmed")) {
    return {
      title: "Your email isn't confirmed yet",
      explanation: "Ask the person who invited you to confirm your account.",
    };
  }
  if (error.status === 429 || msg.includes("rate limit")) {
    return {
      title: "Too many sign-in attempts",
      explanation: "Wait a minute before trying again.",
    };
  }
  if (msg.includes("fetch") || msg.includes("network")) {
    return {
      title: "Can't reach the sign-in service",
      explanation: "Check your connection and try again.",
    };
  }
  return {
    title: "We couldn't sign you in",
    explanation: "Please try again in a moment.",
  };
}
