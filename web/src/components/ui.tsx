"use client";

import type { ReactNode } from "react";
import { ApiError, userMessageForStatus } from "@/lib/errors";

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;
  let message = "Something went wrong.";
  let requestId: string | undefined;
  if (error instanceof ApiError) {
    message = userMessageForStatus(error.status, error.message);
    requestId = error.requestId;
  } else if (error instanceof Error) {
    message = error.message;
  }
  return (
    <div className="banner" role="alert" aria-live="assertive">
      {message}
      {requestId ? <span className="muted"> (ref: {requestId})</span> : null}
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
  // An ambiguous external-action outcome: the side effect MAY have occurred but
  // cannot be proven. Distinct from a definite failure — surfaced as a warning.
  unknown: "warn",
  UNKNOWN: "warn",
};

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge ${STATUS_CLASS[status] ?? ""}`}>{status}</span>;
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
