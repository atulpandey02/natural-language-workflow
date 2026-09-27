"use client";
import { ResponsiveDetails } from "@/components/ResponsiveDetails";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { useMe } from "@/lib/api/hooks";
import { WorkspaceSwitcher } from "./WorkspaceSwitcher";
import { SignOutButton } from "./SignOutButton";

const NAV_GROUPS = [
  {
    caption: "Analyze",
    items: [
      { href: "/", label: "Home", icon: "⌂" },
      { href: "/workflows/new", label: "New analysis", icon: "＋" },
    ],
  },
  {
    caption: "Operate",
    items: [
      { href: "/workflows", label: "Workflows", icon: "◇" },
      { href: "/runs", label: "Runs", icon: "▷" },
      { href: "/approvals", label: "Approvals", icon: "✓" },
    ],
  },
  {
    caption: "Workspace",
    items: [
      { href: "/connectors", label: "Connectors", icon: "⊞" },
      { href: "/members", label: "Members", icon: "⚇" },
      { href: "/settings", label: "Settings", icon: "⚙" },
    ],
  },
];
export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const me = useMe();
  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <ResponsiveDetails className="sidebar" breakpoint={1200}>
        <summary>Navigation</summary>
        <div className="sidebar-content">
          <Link href="/" className="brand">
            <span aria-hidden="true">N</span> NLW <small>PILOT</small>
          </Link>
          <p className="nav-caption">Current workspace</p>
          <WorkspaceSwitcher />
          <nav aria-label="Primary">
            {NAV_GROUPS.map((group) => (
              <div key={group.caption} role="group" aria-labelledby={`nav-${group.caption}`}>
                <p className="nav-caption" id={`nav-${group.caption}`}>
                  {group.caption}
                </p>
                {group.items.map((item) => (
                  <Link
                    href={item.href}
                    key={item.href}
                    aria-current={
                      pathname === item.href ||
                      (item.href === "/workflows" &&
                        pathname.startsWith("/workflows/") &&
                        pathname !== "/workflows/new") ||
                      (item.href === "/runs" && pathname.startsWith("/runs/"))
                        ? "page"
                        : undefined
                    }
                  >
                    <span aria-hidden="true">{item.icon}</span>
                    {item.label}
                  </Link>
                ))}
              </div>
            ))}
          </nav>
          <div className="sidebar-footer">
            <p className="muted small">{me.data?.email}</p>
            <SignOutButton />
          </div>
        </div>
      </ResponsiveDetails>
      <main className="container" id="main-content">
        {children}
      </main>
    </div>
  );
}
