// Membership presentation + usability rules. These MIRROR the backend's
// authoritative checks (FastAPI `_admin_ctx` + the SECURITY DEFINER
// `manage_membership` / invitation functions under RLS); they only decide which
// controls to show. The server remains the only authority.
import type { MemberRole } from "@/lib/api/types";

export const ROLE_LABEL: Record<MemberRole, string> = {
  owner: "Owner",
  admin: "Admin",
  member: "Member",
};

export const ROLE_HELP: Record<MemberRole, string> = {
  owner: "Full control, including other owners.",
  admin: "Invites people, manages connectors and approves actions.",
  member: "Asks questions and runs analyses. Cannot approve actions.",
};

export function roleLabel(role: string | undefined): string {
  return role && role in ROLE_LABEL ? ROLE_LABEL[role as MemberRole] : "Member";
}

export function isManager(role: string | undefined): boolean {
  return role === "owner" || role === "admin";
}

/** Roles an actor may GRANT to an existing member: only an owner grants owner. */
export function assignableRoles(actor: string | undefined): MemberRole[] {
  if (actor === "owner") return ["owner", "admin", "member"];
  if (actor === "admin") return ["admin", "member"];
  return [];
}

/** Invitations may grant admin or member only (never owner), by owner/admin. */
export function invitableRoles(actor: string | undefined): ("admin" | "member")[] {
  return isManager(actor) ? ["member", "admin"] : [];
}

/**
 * Whether the actor sees role/remove controls for a row. Owners' rows are
 * owner-only; nobody manages their own row here (avoids accidental self-lockout;
 * the backend would still keep at least one owner).
 */
export function canManageRow(actor: string | undefined, target: string, isSelf: boolean): boolean {
  if (isSelf || !isManager(actor)) return false;
  return target !== "owner" || actor === "owner";
}

/** The one-time acceptance link for a freshly created invitation token. */
export function invitationLink(origin: string, token: string): string {
  return `${origin}/invitations/accept?token=${encodeURIComponent(token)}`;
}

/** "Member since 26 Sep 2026" — how co-members are told apart without a UUID. */
export function memberSince(joinedAt: string | null | undefined): string {
  if (!joinedAt) return "Workspace member";
  const d = new Date(joinedAt);
  if (Number.isNaN(d.getTime())) return "Workspace member";
  return `Member since ${d.toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  })}, ${d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`;
}
