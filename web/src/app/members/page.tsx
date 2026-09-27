"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { AppShell } from "@/components/AppShell";
import { ErrorBanner, Empty, Loading } from "@/components/ui";
import {
  useChangeMemberRole,
  useCreateInvitation,
  useCurrentWorkspace,
  useInvitations,
  useMe,
  useMembers,
  useRemoveMember,
  useRevokeInvitation,
} from "@/lib/api/hooks";
import type { InvitationOut, MemberOut, MemberRole } from "@/lib/api/types";
import {
  ROLE_HELP,
  assignableRoles,
  canManageRow,
  invitableRoles,
  invitationLink,
  isManager,
  memberSince,
  roleLabel,
} from "@/lib/membership";

// Workspace people + access. The backend (owner/admin checks, the SECURITY
// DEFINER membership/invitation functions and RLS) is the only authority; this
// page hides controls a role cannot use and never shows internal identifiers.
export default function MembersPage() {
  const members = useMembers();
  const me = useMe();
  const current = useCurrentWorkspace();
  const role = current.data?.role;
  const manager = isManager(role);
  // Only admins/owners load invitations; a plain member never fires the request.
  const invitations = useInvitations(manager);

  return (
    <AppShell>
      <p className="eyebrow">WORKSPACE</p>
      <h1>Members</h1>
      <p className="lead muted">
        Everyone here shares this workspace&apos;s analyses, workflows and approvals.
      </p>

      <section className="card" aria-labelledby="people-title">
        <div className="section-heading">
          <h2 id="people-title">People</h2>
          {members.data ? (
            <span className="muted small">
              {members.data.length} {members.data.length === 1 ? "member" : "members"}
            </span>
          ) : null}
        </div>
        {members.isLoading ? <Loading label="Loading members…" /> : null}
        <ErrorBanner error={members.error} />
        {members.data && members.data.length === 0 ? <Empty>No members yet.</Empty> : null}
        {members.data && members.data.length > 0 ? (
          <MemberTable
            rows={members.data}
            actor={role}
            selfId={me.data?.id}
            selfEmail={me.data?.email}
          />
        ) : null}
        {role && !manager ? (
          <p className="muted small" data-testid="member-readonly-note">
            Only owners and admins can invite people or change access.
          </p>
        ) : null}
      </section>

      {manager ? (
        <>
          <PendingInvitations
            data={invitations.data}
            isLoading={invitations.isLoading}
            error={invitations.error}
          />
          <InviteForm actor={role} />
        </>
      ) : null}
    </AppShell>
  );
}

function MemberTable({
  rows,
  actor,
  selfId,
  selfEmail,
}: {
  rows: MemberOut[];
  actor: string | undefined;
  selfId: string | undefined;
  selfEmail: string | undefined;
}) {
  const changeRole = useChangeMemberRole();
  const removeMember = useRemoveMember();
  const [confirming, setConfirming] = useState<string | null>(null);
  const showManage = isManager(actor);

  return (
    <>
      <ErrorBanner error={changeRole.error} />
      <ErrorBanner error={removeMember.error} />
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Workspace members">
        <table>
          <thead>
            <tr>
              <th scope="col">Person</th>
              <th scope="col">Role</th>
              {showManage ? <th scope="col">Access</th> : null}
            </tr>
          </thead>
          <tbody>
            {rows.map((m, i) => {
              const self = m.user_id === selfId;
              const who = self ? `You · ${selfEmail ?? "signed in"}` : memberSince(m.joined_at);
              const manageable = canManageRow(actor, m.role, self);
              const label = self ? "you" : `member ${i + 1}`;
              return (
                <tr key={m.user_id} data-testid="member-row">
                  <th scope="row">{who}</th>
                  <td>
                    <span className="role-pill" title={ROLE_HELP[m.role]}>
                      {roleLabel(m.role)}
                    </span>
                  </td>
                  {showManage ? (
                    <td>
                      {manageable ? (
                        confirming === m.user_id ? (
                          <div
                            className="row"
                            role="group"
                            aria-label={`Confirm removal of ${label}`}
                          >
                            <span className="small">Remove access now?</span>
                            <button
                              className="danger"
                              disabled={removeMember.isPending}
                              onClick={() =>
                                removeMember.mutate(m.user_id, {
                                  onSettled: () => setConfirming(null),
                                })
                              }
                            >
                              {removeMember.isPending ? "Removing…" : "Remove"}
                            </button>
                            <button className="secondary" onClick={() => setConfirming(null)}>
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <div className="row">
                            <label className="sr-only" htmlFor={`role-${i}`}>
                              Role for {label}
                            </label>
                            <select
                              id={`role-${i}`}
                              value={m.role}
                              disabled={changeRole.isPending}
                              onChange={(e) =>
                                changeRole.mutate({
                                  userId: m.user_id,
                                  role: e.target.value as MemberRole,
                                })
                              }
                            >
                              {assignableRoles(actor).map((r) => (
                                <option key={r} value={r}>
                                  {roleLabel(r)}
                                </option>
                              ))}
                            </select>
                            <button className="secondary" onClick={() => setConfirming(m.user_id)}>
                              Remove…
                            </button>
                          </div>
                        )
                      ) : (
                        <span className="muted small">
                          {self ? "Your access" : "Only an owner can change an owner"}
                        </span>
                      )}
                    </td>
                  ) : null}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function PendingInvitations({
  data,
  isLoading,
  error,
}: {
  data: InvitationOut[] | undefined;
  isLoading: boolean;
  error: unknown;
}) {
  const revoke = useRevokeInvitation();
  const [confirming, setConfirming] = useState<string | null>(null);
  return (
    <section className="card" aria-labelledby="pending-title">
      <h2 id="pending-title">Pending invitations</h2>
      {isLoading ? <Loading label="Loading invitations…" /> : null}
      <ErrorBanner error={error} />
      <ErrorBanner error={revoke.error} />
      {data && data.length === 0 ? <Empty>No pending invitations.</Empty> : null}
      {data && data.length > 0 ? (
        <div className="table-scroll" tabIndex={0} role="region" aria-label="Pending invitations">
          <table>
            <thead>
              <tr>
                <th scope="col">Email</th>
                <th scope="col">Role</th>
                <th scope="col">Expires</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.map((inv) => (
                <tr key={inv.id} data-testid="invitation-row">
                  <th scope="row">{inv.email}</th>
                  <td>{roleLabel(inv.role)}</td>
                  <td className="muted">{new Date(inv.expires_at).toLocaleString()}</td>
                  <td>
                    {confirming === inv.id ? (
                      <div
                        className="row"
                        role="group"
                        aria-label={`Confirm revoking ${inv.email}`}
                      >
                        <button
                          className="danger"
                          disabled={revoke.isPending}
                          onClick={() =>
                            revoke.mutate(inv.id, { onSettled: () => setConfirming(null) })
                          }
                        >
                          {revoke.isPending ? "Revoking…" : "Revoke"}
                        </button>
                        <button className="secondary" onClick={() => setConfirming(null)}>
                          Keep
                        </button>
                      </div>
                    ) : (
                      <button
                        className="secondary"
                        aria-label={`Revoke invitation for ${inv.email}`}
                        onClick={() => setConfirming(inv.id)}
                      >
                        Revoke…
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

interface InviteFormValues {
  email: string;
  role: "admin" | "member";
}

function InviteForm({ actor }: { actor: string | undefined }) {
  const create = useCreateInvitation();
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<InviteFormValues>({ defaultValues: { email: "", role: "member" } });
  // The acceptance link embeds the one-time token returned ONCE by the API. It is
  // held only in this render state — never stored, logged or shown unless the
  // admin chooses "Show link" — and dropped on "Done" or the next invitation.
  const [created, setCreated] = useState<{ email: string; link: string; expires: string } | null>(
    null,
  );
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  async function onSubmit(values: InviteFormValues) {
    setCreated(null);
    setRevealed(false);
    setCopied(false);
    try {
      const out = await create.mutateAsync({ email: values.email.trim(), role: values.role });
      setCreated({
        email: out.email,
        link: invitationLink(window.location.origin, out.token),
        expires: out.expires_at,
      });
      reset({ email: "", role: "member" });
    } catch {
      /* the mutation's error is rendered below */
    }
  }

  async function copy() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.link);
      setCopied(true);
    } catch {
      setRevealed(true); // clipboard blocked: let the admin copy it by hand
    }
  }

  return (
    <section className="card" aria-labelledby="invite-title">
      <h2 id="invite-title">Invite someone</h2>
      <p className="muted small">
        They sign in with this email, open the link you share, and join as the role you pick.
        Invitation-only pilot: there is no public sign-up.
      </p>
      {created ? (
        <div className="notice" role="status" data-testid="invitation-created">
          <strong>Invitation ready for {created.email}.</strong>
          <p className="small">
            Share this link over a trusted channel. It works once, only for that email, and expires{" "}
            {new Date(created.expires).toLocaleString()}. It will not be shown again.
          </p>
          <div className="row">
            <button type="button" onClick={copy}>
              {copied ? "Link copied" : "Copy invitation link"}
            </button>
            <button type="button" className="secondary" onClick={() => setRevealed((v) => !v)}>
              {revealed ? "Hide link" : "Show link"}
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                setCreated(null);
                setRevealed(false);
              }}
            >
              Done
            </button>
          </div>
          {revealed ? (
            <input
              aria-label="Invitation link"
              data-testid="invitation-link"
              readOnly
              value={created.link}
              onFocus={(e) => e.currentTarget.select()}
            />
          ) : null}
        </div>
      ) : null}
      <form aria-label="Invite someone" onSubmit={handleSubmit(onSubmit)} noValidate>
        <ErrorBanner error={create.error} />
        <label htmlFor="invite-email">Email address</label>
        <input
          id="invite-email"
          type="email"
          autoComplete="off"
          aria-invalid={errors.email ? true : undefined}
          aria-describedby={errors.email ? "invite-email-error" : undefined}
          {...register("email", {
            required: "Enter the email address they sign in with.",
            pattern: {
              value: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
              message: "Enter a valid email address.",
            },
          })}
        />
        {errors.email ? (
          <p className="field-error" id="invite-email-error">
            {errors.email.message}
          </p>
        ) : null}
        <label htmlFor="invite-role">Role</label>
        <select id="invite-role" {...register("role")}>
          {invitableRoles(actor).map((r) => (
            <option key={r} value={r}>
              {roleLabel(r)} — {ROLE_HELP[r]}
            </option>
          ))}
        </select>
        <div style={{ marginTop: 12 }}>
          <button type="submit" disabled={create.isPending}>
            {create.isPending ? "Creating invitation…" : "Create invitation"}
          </button>
        </div>
      </form>
    </section>
  );
}
