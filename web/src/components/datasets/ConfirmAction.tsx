"use client";

import { useEffect, useId, useRef, useState, type ReactNode } from "react";

/**
 * A two-step destructive control: the first press explains the consequence
 * and moves focus to the explicitly labelled confirm button; the second press
 * performs it. Both steps are ordinary buttons, so it works by keyboard alone.
 */
export function ConfirmAction({
  label,
  confirmLabel,
  children,
  onConfirm,
  pending,
  disabled,
}: {
  label: string;
  confirmLabel: string;
  /** What will happen, shown before the second press. */
  children: ReactNode;
  onConfirm: () => void;
  pending?: boolean;
  disabled?: boolean;
}) {
  const [asking, setAsking] = useState(false);
  const id = useId();
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (asking) confirmRef.current?.focus();
  }, [asking]);
  if (!asking) {
    return (
      <button
        type="button"
        className="secondary"
        disabled={disabled || pending}
        onClick={() => setAsking(true)}
      >
        {pending ? "Requesting…" : label}
      </button>
    );
  }
  return (
    <div className="notice" role="group" aria-labelledby={id}>
      <p id={id}>{children}</p>
      <div className="row">
        <button
          type="button"
          ref={confirmRef}
          onClick={() => {
            setAsking(false);
            onConfirm();
          }}
        >
          {confirmLabel}
        </button>
        <button type="button" className="secondary" onClick={() => setAsking(false)}>
          Cancel
        </button>
      </div>
    </div>
  );
}
