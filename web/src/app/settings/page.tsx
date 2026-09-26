"use client";
import Link from "next/link";
import { AppShell } from "@/components/AppShell";
export default function SettingsPage() {
  return (
    <AppShell>
      <p className="eyebrow">WORKSPACE</p>
      <h1>Settings</h1>
      <div className="card">
        <h2>People and access</h2>
        <p>Manage workspace membership, roles and invitations.</p>
        <Link href="/members">Manage members</Link>
      </div>
      <div className="card">
        <h2>Scheduled work</h2>
        <p>Review recurring workflows and their authorization state.</p>
        <Link href="/schedules">Manage schedules</Link>
      </div>
    </AppShell>
  );
}
