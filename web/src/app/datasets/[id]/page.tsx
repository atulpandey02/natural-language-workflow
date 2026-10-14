"use client";

import { Suspense, use } from "react";
import { AppShell } from "@/components/AppShell";
import { Loading } from "@/components/ui";
import { DatasetDetail } from "@/components/datasets/DatasetDetail";

export default function DatasetPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <AppShell>
      <Suspense fallback={<Loading />}>
        <DatasetDetail id={id} />
      </Suspense>
    </AppShell>
  );
}
