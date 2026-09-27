"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { safeNextPath } from "@/lib/next-path";
import { describeAuthError } from "@/lib/friendly-errors";
import { EvidenceChain } from "@/components/EvidenceChain";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const CAPABILITIES = [
  {
    title: "Grounded analytics",
    body: "Every figure and finding traces back to the step that produced it.",
  },
  {
    title: "Durable execution",
    body: "Workflows are checkpointed, resumable and never silently retried.",
  },
  {
    title: "Human approval",
    body: "Actions that leave NLW wait for a second person to approve them.",
  },
];

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<ReturnType<typeof describeAuthError>>(null);
  const [busy, setBusy] = useState(false);
  // An allowlisted return path (only the invitation-accept page). Read once, kept
  // in memory, and scrubbed from the address bar so the token does not linger.
  const next = useRef<string | null>(null);
  const [joining, setJoining] = useState(false);
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    next.current = safeNextPath(params.get("next"));
    setJoining(next.current !== null);
    if (params.has("next")) window.history.replaceState(null, "", "/login");
  }, []);

  const emailError =
    touched && !EMAIL_RE.test(email.trim()) ? "Enter your work email address." : null;
  const passwordError = touched && !password ? "Enter your password." : null;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!EMAIL_RE.test(email.trim()) || !password) return;
    setBusy(true);
    setError(null);
    const { error } = await getSupabaseBrowserClient().auth.signInWithPassword({
      email: email.trim(),
      password,
    });
    if (error) {
      setBusy(false);
      setError(describeAuthError(error));
      return;
    }
    router.push(next.current ?? "/");
    router.refresh();
  }

  return (
    <main className="auth-page" id="main-content">
      <section className="auth-form-side auth-card" aria-labelledby="signin-title">
        <p className="brand" aria-label="NLW pilot">
          <span aria-hidden="true">N</span> NLW <small>PILOT</small>
        </p>
        <h1 id="signin-title">{joining ? "Sign in to accept your invitation" : "Sign in"}</h1>
        <p className="subtitle">
          {joining
            ? "Use the email address your invitation was sent to."
            : "Welcome back. Use your work email."}
        </p>
        <form onSubmit={onSubmit} noValidate aria-describedby="signin-help">
          {error ? (
            <div className="error-panel" role="alert" data-testid="login-error">
              <strong>{error.title}</strong>
              <p>{error.explanation}</p>
            </div>
          ) : null}
          <label htmlFor="email">Work email</label>
          <input
            id="email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            aria-invalid={emailError ? true : undefined}
            aria-describedby={emailError ? "email-error" : undefined}
            required
          />
          {emailError ? (
            <p className="field-error" id="email-error">
              {emailError}
            </p>
          ) : null}
          <label htmlFor="password">Password</label>
          <div className="password-field">
            <input
              id="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              aria-invalid={passwordError ? true : undefined}
              aria-describedby={passwordError ? "password-error" : undefined}
              required
            />
            <button
              type="button"
              className="secondary"
              aria-pressed={showPassword}
              aria-controls="password"
              onClick={() => setShowPassword((v) => !v)}
            >
              {showPassword ? "Hide" : "Show"}
              <span className="sr-only"> password</span>
            </button>
          </div>
          {passwordError ? (
            <p className="field-error" id="password-error">
              {passwordError}
            </p>
          ) : null}
          <button type="submit" className="auth-submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="muted small auth-help" id="signin-help">
            No account? Access is by invitation — ask your workspace owner or administrator.
          </p>
        </form>
      </section>

      <section className="auth-intro" aria-labelledby="auth-headline">
        <p className="eyebrow">Governed analytics workflows</p>
        <h2 id="auth-headline">Turn business questions into governed workflows</h2>
        <EvidenceChain current="Request" />
        <ul className="capability-list">
          {CAPABILITIES.map((c) => (
            <li key={c.title}>
              <strong>{c.title}</strong>
              <span>{c.body}</span>
            </li>
          ))}
        </ul>
        <p className="pilot-note small" data-testid="pilot-note">
          Invitation-only pilot. All sample data is synthetic — no real customer or personal
          information.
        </p>
      </section>
    </main>
  );
}
