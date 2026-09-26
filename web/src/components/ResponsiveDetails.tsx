"use client";
import { useEffect, useRef, type ReactNode } from "react";

/** Native disclosure: keyboard-operable nonmodal drawer at smaller widths. */
export function ResponsiveDetails({
  children,
  className,
  breakpoint,
}: {
  children: ReactNode;
  className: string;
  breakpoint: number;
}) {
  const ref = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const media = window.matchMedia(`(min-width: ${breakpoint + 1}px)`);
    const sync = () => {
      if (ref.current) ref.current.open = media.matches;
    };
    sync();
    media.addEventListener("change", sync);
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !media.matches && ref.current?.open) {
        ref.current.open = false;
        ref.current.querySelector("summary")?.focus();
      }
    };
    const panel = ref.current;
    panel?.addEventListener("keydown", escape);
    return () => {
      media.removeEventListener("change", sync);
      panel?.removeEventListener("keydown", escape);
    };
  }, [breakpoint]);
  return (
    <details ref={ref} open className={className}>
      {children}
    </details>
  );
}
