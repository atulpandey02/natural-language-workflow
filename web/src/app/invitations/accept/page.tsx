"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAcceptInvitation } from "@/lib/api/hooks";
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

  return (
    <main className="container" style={{ maxWidth: 480, paddingTop: 48 }}>
      <h1>Accept invitation</h1>

      {phase === "accepting" ? <Loading label="Redeeming invitation…" /> : null}

      {phase === "failed" ? (
        <div className="banner" role="alert" aria-live="assertive">
          {FAILURE}
        </div>
      ) : null}

      {result && (phase === "accepted" || phase === "entering") ? (
        <div className="card" data-testid="invitation-accepted">
          <strong>You&rsquo;ve joined the workspace.</strong>
          <p className="muted">
            Workspace <code>{result.workspace_id}</code> · role <strong>{result.role}</strong>
          </p>
          {enterError ? (
            <div className="banner" role="alert">
              Could not open the workspace. Please try again.
            </div>
          ) : null}
          <button onClick={enter} disabled={phase === "entering"}>
            {phase === "entering" ? "Opening…" : "Continue to workspace"}
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
