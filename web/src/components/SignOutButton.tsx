"use client";

import { useRouter } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

export function SignOutButton() {
  const router = useRouter();
  const qc = useQueryClient();

  async function signOut() {
    await getSupabaseBrowserClient().auth.signOut();
    qc.clear();
    router.push("/login");
    router.refresh();
  }

  return (
    <button className="secondary" onClick={signOut}>
      Sign out
    </button>
  );
}
