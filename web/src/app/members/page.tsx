"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading, RoleGate, StatusBadge, canApprove } from "@/components/ui";
import {
  useChangeMemberRole,
  useCreateInvitation,
  useCurrentWorkspace,
  useInvitations,
  useMembers,
  useRemoveMember,
  useRevokeInvitation,
} from "@/lib/api/hooks";
import type { InvitationOut, MemberRole } from "@/lib/api/types";

const MEMBER_ROLES: MemberRole[] = ["owner", "admin", "member"];

export default function MembersPage() {
  const members = useMembers();
  const current = useCurrentWorkspace();
  const role = current.data?.role;
  const isManager = canApprove(role);

  const changeRole = useChangeMemberRole();
  const removeMember = useRemoveMember();
  // Only admins/owners load invitations; a plain member never fires the request.
  const invitations = useInvitations(isManager);

  return (
    <AppShell>
      <h1>Members</h1>
      {members.isLoading ? <Loading /> : null}
      <ErrorBanner error={members.error} />
      {/* 403/409 from a role change or removal (e.g. removing the last owner) is
          surfaced with the backend's stable message. Backend + RLS remain
          authoritative; the gating below is usability only. */}
      <ErrorBanner error={changeRole.error} />
      <ErrorBanner error={removeMember.error} />

      {members.data && members.data.length === 0 ? <Empty>No members yet.</Empty> : null}

      {members.data && members.data.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <RoleGate role={role} allow={["owner", "admin"]}>
                <th>Manage</th>
              </RoleGate>
            </tr>
          </thead>
          <tbody>
            {members.data.map((m) => (
              <tr key={m.user_id}>
                <td className="muted">{m.user_id}</td>
                <td>{m.role}</td>
                <RoleGate role={role} allow={["owner", "admin"]}>
                  <td>
                    <div className="row">
                      <select
                        aria-label={`role for ${m.user_id}`}
                        value={m.role}
                        disabled={changeRole.isPending}
                        onChange={(e) =>
                          changeRole.mutate({
                            userId: m.user_id,
                            role: e.target.value as MemberRole,
                          })
                        }
                      >
                        {MEMBER_ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                      <button
                        className="secondary"
                        aria-label={`remove ${m.user_id}`}
                        disabled={removeMember.isPending}
                        onClick={() => removeMember.mutate(m.user_id)}
                      >
                        Remove
                      </button>
                    </div>
                  </td>
                </RoleGate>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {role && !isManager ? (
        <p className="muted">An admin or owner must manage members and invitations.</p>
      ) : null}

      <RoleGate role={role} allow={["owner", "admin"]}>
        <Invitations
          data={invitations.data}
          isLoading={invitations.isLoading}
          error={invitations.error}
        />
      </RoleGate>
    </AppShell>
  );
}

interface InviteFormValues {
  email: string;
  role: "admin" | "member";
}

function Invitations({
  data,
  isLoading,
  error,
}: {
  data: InvitationOut[] | undefined;
  isLoading: boolean;
  error: unknown;
}) {
  const create = useCreateInvitation();
  const revoke = useRevokeInvitation();
  const { register, handleSubmit, reset } = useForm<InviteFormValues>({
    defaultValues: { email: "", role: "member" },
  });

  // The raw invitation token is returned exactly once by POST /invitations. It
  // lives ONLY in this transient render state for manual copying — never written
  // to localStorage, never logged, and dropped as soon as the operator dismisses
  // it or creates another invitation.
  const [token, setToken] = useState<string | null>(null);
  const [tokenEmail, setTokenEmail] = useState<string | null>(null);

  async function onSubmit(values: InviteFormValues) {
    setToken(null);
    const created = await create.mutateAsync({ email: values.email, role: values.role });
    setToken(created.token);
    setTokenEmail(created.email);
    reset({ email: "", role: "member" });
  }

  return (
    <section style={{ marginTop: 24 }}>
      <h2 style={{ fontSize: 16 }}>Pending invitations</h2>
      {isLoading ? <Loading /> : null}
      <ErrorBanner error={error} />
      <ErrorBanner error={revoke.error} />

      {data && data.length === 0 ? <Empty>No pending invitations.</Empty> : null}
      {data && data.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Expires</th>
              <th>Revoke</th>
            </tr>
          </thead>
          <tbody>
            {data.map((inv) => (
              <tr key={inv.id}>
                <td>{inv.email}</td>
                <td>{inv.role}</td>
                <td>
                  <StatusBadge status={inv.status} />
                </td>
                <td className="muted">{new Date(inv.expires_at).toLocaleString()}</td>
                <td>
                  <button
                    className="secondary"
                    aria-label={`revoke ${inv.email}`}
                    disabled={revoke.isPending}
                    onClick={() => revoke.mutate(inv.id)}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {token ? (
        <div className="card" role="status" data-testid="invitation-token">
          <strong>Invitation created{tokenEmail ? ` for ${tokenEmail}` : ""}.</strong>
          <p className="muted" style={{ marginBottom: 4 }}>
            Copy this token now — it is shown only once and is never stored by this console. Share
            it over a trusted channel so the invitee can accept.
          </p>
          <pre style={{ whiteSpace: "pre-wrap", userSelect: "all" }}>{token}</pre>
          <button
            className="secondary"
            onClick={() => {
              setToken(null);
              setTokenEmail(null);
            }}
          >
            Done
          </button>
        </div>
      ) : null}

      <form
        className="card"
        aria-label="invite member"
        onSubmit={handleSubmit(onSubmit)}
        noValidate
      >
        <h3 style={{ marginTop: 0, fontSize: 15 }}>Invite a member</h3>
        <ErrorBanner error={create.error} />
        <label htmlFor="invite-email">Email</label>
        <input id="invite-email" type="email" {...register("email", { required: true })} />
        <label htmlFor="invite-role">Role</label>
        <select id="invite-role" {...register("role")}>
          <option value="member">member</option>
          <option value="admin">admin</option>
        </select>
        <div style={{ marginTop: 12 }}>
          <button type="submit" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create invitation"}
          </button>
        </div>
      </form>
    </section>
  );
}
