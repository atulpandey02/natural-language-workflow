// Truthful schedule status for the UI. Precedence: a fail-closed authorization
// block wins over `enabled` (a blocked schedule creates no occurrences even while
// enabled=true), then enabled -> active, otherwise disabled.
import type { ScheduleOut } from "@/lib/api/types";

export type ScheduleStatus = "blocked" | "active" | "disabled";

export function scheduleStatus(s: Pick<ScheduleOut, "enabled" | "blocked_reason">): ScheduleStatus {
  if (s.blocked_reason) return "blocked";
  return s.enabled ? "active" : "disabled";
}

// Stable, low-cardinality reason codes set by the scheduler (migration 0020).
// Only these are rendered verbatim as prose; anything else gets the generic
// sentence so no internal SQL/policy detail can ever reach the screen.
const REASON_TEXT: Record<string, string> = {
  CREATOR_NOT_A_MEMBER:
    "Blocked: the person who created this schedule is no longer a member of this workspace. " +
    "It will not run until an admin restores their membership and unblocks it, or recreates it.",
  CREATOR_ROLE_INSUFFICIENT:
    "Blocked: the person who created this schedule no longer has the admin or owner role. " +
    "It will not run until an admin restores their role and unblocks it, or recreates it.",
};

const GENERIC_TEXT =
  "Blocked: the person who created this schedule is no longer authorized to run it. " +
  "It will not run until an admin restores their authorization and unblocks it, or recreates it.";

/** Human-readable explanation for a blocked schedule; null when not blocked. */
export function blockedReasonText(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return REASON_TEXT[reason] ?? GENERIC_TEXT;
}
