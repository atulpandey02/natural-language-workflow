"use client";

import Link from "next/link";
import { Suspense, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAcceptInvitation, useMe, useWorkspaces } from "@/lib/api/hooks";
import { roleLabel } from "@/lib/membership";
import { hardNavigate, postWorkspaceSelection } from "@/lib/workspace-client";
import { ApiError } from "@/lib/errors";
import { Loading } from "@/components/ui";
import type { InvitationAcceptedOut } from "@/lib/api/types";

// A stable, non-specific failure message. We never leak backend specifics
// (expired vs. already-used vs. wrong-workspace) to the accepting user.
const FAILURE = "This invitation is not valid.";

type Phase = "accepting" | "accepted" | "failed" | "entering";

function AcceptInner() {
  const router = useRouter();
  const params = useSearchParams();
  const accept = useAcceptInvitation();
  const me = useMe();
  const workspaces = useWorkspaces();

  const [phase, setPhase] = useState<Phase>("accepting");
  const [result, setResult] = useState<InvitationAcceptedOut | null>(null);
  const [enterError, setEnterError] = useState(false);
  // Guard against React StrictMode / re-render double invocation: the token is
  // redeemed exactly once.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    // Copy the raw token out of the URL, use it once, then drop it. It is never
    // written to localStorage, never logged, and stripped from the address bar
    // once the request resolves so it does not linger in history.
    const token = params.get("token") ?? "";

    async function run() {
      if (!token) {
        setPhase("failed");
        return;
      }
      try {
        const out = await accept.mutateAsync(token);
        setResult(out);
        setPhase("accepted");
      } catch (err) {
        // An unauthenticated caller is bounced to sign in (mirrors the login
        // redirect). Any other failure shows the stable, non-specific message.
        if (err instanceof ApiError && err.status === 401) {
          router.replace("/login");
          return;
        }
        setPhase("failed");
      } finally {
        // Remove the token from the URL/history regardless of outcome.
        if (typeof window !== "undefined") {
          window.history.replaceState(null, "", "/invitations/accept");
        }
      }
    }
    void run();
    // Intentionally run once on mount; `accept`/`router`/`params` are stable for
    // this purpose and the ref prevents a second redemption.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function enter() {
    if (!result) return;
    setEnterError(false);
    setPhase("entering");
    try {
      await postWorkspaceSelection(result.workspace_id);
    } catch {
      setEnterError(true);
      setPhase("accepted");
      return;
    }
    // Tenant change → full navigation resets router/RSC + TanStack + client state.
    hardNavigate("/");
  }

  const joined = result ? workspaces.data?.find((w) => w.id === result.workspace_id) : undefined;

  return (
    <main className="container auth-page" style={{ maxWidth: 520, paddingTop: 48 }}>
      <p className="eyebrow">NLW PILOT · INVITATION</p>
      <h1>Join a workspace</h1>
      {me.data?.email ? (
        <p className="muted small" data-testid="accept-identity">
          Signed in as {me.data.email}
        </p>
      ) : null}
      {phase === "accepting" ? <Loading label="Checking your invitation…" /> : null}

      {phase === "failed" ? (
        <div
          className="error-panel"
          role="alert"
          aria-live="assertive"
          data-testid="invitation-failed"
        >
          <strong>{FAILURE}</strong>
          <p>
            Invitations work once, only for the email address they were sent to, and expire after a
            few days.
          </p>
          <p>
            Check that you are signed in with the invited email, or ask the workspace owner or an
            admin for a new invitation.
          </p>
          <p>
            <Link href="/">Go to your workspaces</Link>
          </p>
        </div>
      ) : null}

      {result && (phase === "accepted" || phase === "entering") ? (
        <div className="card" data-testid="invitation-accepted">
          <strong>
            You&rsquo;ve joined {joined ? joined.name : "the workspace"} as {roleLabel(result.role)}
            .
          </strong>
          <p className="muted">
            You can now see its analyses and workflows
            {result.role === "member" ? "." : ", and review approvals requested by others."}
          </p>
          {enterError ? (
            <div className="error-panel" role="alert">
              <strong>We couldn&rsquo;t open the workspace.</strong>
              <p>Please try again. If it keeps happening, sign out and back in.</p>
            </div>
          ) : null}
          <button onClick={enter} disabled={phase === "entering"}>
            {phase === "entering" ? "Opening…" : "Open workspace"}
          </button>
        </div>
      ) : null}
    </main>
  );
}

export default function AcceptInvitationPage() {
  // useSearchParams requires a Suspense boundary during prerender.
  return (
    <Suspense fallback={<Loading label="Loading…" />}>
      <AcceptInner />
    </Suspense>
  );
}
