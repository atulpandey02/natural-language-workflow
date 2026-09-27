"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { safeNextPath } from "@/lib/next-path";
import { describeAuthError } from "@/lib/friendly-errors";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<ReturnType<typeof describeAuthError>>(null);
  const [busy, setBusy] = useState(false);
  // An allowlisted return path (only the invitation-accept page). Read once, kept
  // in memory, and scrubbed from the address bar so the token does not linger.
  const next = useRef<string | null>(null);
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    next.current = safeNextPath(params.get("next"));
    if (params.has("next")) window.history.replaceState(null, "", "/login");
  }, []);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const { error } = await getSupabaseBrowserClient().auth.signInWithPassword({ email, password });
    setBusy(false);
    if (error) {
      setError(describeAuthError(error));
      return;
    }
    router.push(next.current ?? "/");
    router.refresh();
  }

  return (
    <main className="container" style={{ maxWidth: 380, paddingTop: 64 }}>
      <h1>Sign in</h1>
      <p className="muted">Access your natural-language workflow console.</p>
      <form onSubmit={onSubmit} noValidate>
        {error ? (
          <div className="error-panel" role="alert" data-testid="login-error">
            <strong>{error.title}</strong>
            <p>{error.explanation}</p>
          </div>
        ) : null}
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <div style={{ marginTop: 16 }}>
          <button type="submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </div>
      </form>
    </main>
  );
}
