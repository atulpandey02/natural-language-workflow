"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "./client";
import { type Dataset, analyticsSchema } from "@/lib/analytics";
import type { PlanProposalOut } from "./types";

export function useDatasets() {
  return useQuery({
    queryKey: ["analytics-datasets"],
    queryFn: () => api.get<Dataset[]>("/analytics/datasets"),
  });
}
export function useRunAnalytics(id: string) {
  return useQuery({
    queryKey: ["run", id, "analytics"],
    queryFn: async () => {
      const parsed = analyticsSchema.safeParse(await api.get<unknown>(`/runs/${id}/analytics`));
      if (!parsed.success)
        throw new Error("This analysis could not be validated. No charts have been shown.");
      return parsed.data;
    },
    enabled: Boolean(id),
    refetchInterval: (q) =>
      q.state.data &&
      ["COMPLETED", "FAILED", "FAILED_WITH_UNKNOWN"].includes(q.state.data.run_outcome)
        ? false
        : 4000,
  });
}
export function useSlackProposal(id: string) {
  return useMutation({
    mutationFn: (selection: { connector_id: string; channel: string }) =>
      api.post<PlanProposalOut>(`/runs/${id}/slack-proposal`, selection),
  });
}
