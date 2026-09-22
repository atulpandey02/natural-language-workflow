"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { useMe } from "@/lib/api/hooks";
import { WorkspaceSwitcher } from "./WorkspaceSwitcher";
import { SignOutButton } from "./SignOutButton";

const NAV = [
  { href: "/", label: "Dashboard" },
  { href: "/workflows", label: "Workflows" },
  { href: "/connectors", label: "Connectors" },
  { href: "/members", label: "Members" },
  { href: "/approvals", label: "Approvals" },
  { href: "/schedules", label: "Schedules" },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const me = useMe();

  return (
    <>
      <header className="shell">
        <div className="inner">
          <strong>NLW</strong>
          <nav aria-label="Primary">
            {NAV.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                aria-current={
                  pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href))
                    ? "page"
                    : undefined
                }
              >
                {item.label}
              </Link>
            ))}
          </nav>
          <span className="spacer" />
          <WorkspaceSwitcher />
          {me.data ? <span className="muted">{me.data.email}</span> : null}
          <SignOutButton />
        </div>
      </header>
      <main className="container">{children}</main>
    </>
  );
}
