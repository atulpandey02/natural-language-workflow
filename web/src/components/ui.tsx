"use client";

import type { ReactNode } from "react";
import { statusLabel } from "@/lib/plan-language";
import {
  RETRY_TEXT,
  describeError,
  describeOutcome,
  type FriendlyError,
} from "@/lib/friendly-errors";

/**
 * The ONE way pages show a failure: a short title, a plain explanation, a safe
 * next step and retry guidance (lib/friendly-errors). Raw provider/API/Pydantic
 * text, internal identifiers and stack traces are never rendered; only a
 * sanitized request reference is.
 */
export function ErrorBanner({ error }: { error: unknown }) {
  const friendly = describeError(error);
  if (!friendly) return null;
  return <FriendlyPanel friendly={friendly} />;
}

/** Friendly explanation of a non-successful workflow outcome (FAILED, PARTIAL, UNKNOWN). */
export function OutcomeNotice({ outcome }: { outcome: string | undefined }) {
  const friendly = describeOutcome(outcome);
  if (!friendly) return null;
  return <FriendlyPanel friendly={friendly} live="polite" />;
}

function FriendlyPanel({
  friendly,
  live = "assertive",
}: {
  friendly: FriendlyError;
  live?: "polite" | "assertive";
}) {
  const tone = friendly.tone === "error" ? "" : ` ${friendly.tone}`;
  return (
    <div
      className={`error-panel${tone}`}
      role={live === "assertive" ? "alert" : "status"}
      aria-live={live}
      data-testid="friendly-error"
      data-kind={friendly.kind}
    >
      <strong>{friendly.title}</strong>
      <p>{friendly.explanation}</p>
      {friendly.changed ? <p className="changed">{friendly.changed}</p> : null}
      <p>
        {friendly.action} <span className="muted">{RETRY_TEXT[friendly.retry]}</span>
      </p>
      {friendly.reference ? <p className="ref">Reference: {friendly.reference}</p> : null}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="muted" role="status" aria-live="polite">
      {label}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

const STATUS_CLASS: Record<string, string> = {
  COMPLETED: "ok",
  SUCCESS: "ok",
  active: "ok",
  approved: "ok",
  FAILED: "fail",
  rejected: "fail",
  error: "fail",
  RUNNING: "run",
  PENDING: "run",
  pending: "warn",
  WAITING_APPROVAL: "warn",
  unchecked: "warn",
  disabled: "warn",
  // A schedule whose creator lost authorization: it will NOT run (fail-closed),
  // regardless of `enabled` — surfaced as a failure state needing admin action.
  blocked: "fail",
  // An ambiguous external-action outcome: the side effect MAY have occurred but
  // cannot be proven. Distinct from a definite failure — surfaced as a warning.
  unknown: "warn",
  UNKNOWN: "warn",
  SKIPPED: "skip",
  FAILED_WITH_UNKNOWN: "warn",
  ACTION_OUTCOME_UNKNOWN: "warn",
  PARTIAL: "warn",
  NEEDS_APPROVAL: "warn",
  NEEDS_CLARIFICATION: "warn",
  PASS: "ok",
  REJECT: "fail",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`badge ${STATUS_CLASS[status] ?? ""}`} data-status={status}>
      {statusLabel(status)}
    </span>
  );
}

/** Convenience UI gate. Backend RLS remains authoritative (M10 change §16). */
export function RoleGate({
  role,
  allow,
  children,
}: {
  role: string | undefined;
  allow: string[];
  children: ReactNode;
}) {
  if (!role || !allow.includes(role)) return null;
  return <>{children}</>;
}

export function canApprove(role: string | undefined): boolean {
  return role === "owner" || role === "admin";
}
