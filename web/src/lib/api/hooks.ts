"use client";

import { useCallback, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import type {
  ApprovalDecisionOut,
  ApprovalOut,
  ConnectorOut,
  InvitationAcceptedOut,
  InvitationCreatedOut,
  InvitationOut,
  MaterializeOut,
  MemberOut,
  MemberRole,
  PlanProposalOut,
  RunCreateOut,
  RunOut,
  ScheduleOut,
  StepRunOut,
  ExternalActionOut,
  TenantContextOut,
  ToolOut,
  UserOut,
  WorkflowDetailOut,
  WorkflowOut,
  WorkspaceOut,
} from "@/lib/api/types";

// Bounded polling intervals (M10 D4). No WebSockets.
const RUN_POLL_MS = 4000;
const APPROVALS_POLL_MS = 10000;
const SCHEDULES_POLL_MS = 30000;

const TERMINAL = new Set(["COMPLETED", "FAILED"]);

export function useMe() {
  return useQuery({ queryKey: ["me"], queryFn: () => api.get<UserOut>("/me") });
}

export function useWorkspaces() {
  return useQuery({
    queryKey: ["workspaces"],
    queryFn: () => api.get<WorkspaceOut[]>("/workspaces"),
  });
}

export function useCurrentWorkspace() {
  return useQuery({
    queryKey: ["workspace-current"],
    queryFn: () => api.get<TenantContextOut>("/workspaces/current"),
  });
}

export function useCreateWorkspace() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.post<WorkspaceOut>("/workspaces", { name }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["workspaces"] }),
  });
}

export function useConnectors() {
  return useQuery({
    queryKey: ["connectors"],
    queryFn: () => api.get<ConnectorOut[]>("/connectors"),
  });
}

export function useTools() {
  return useQuery({ queryKey: ["tools"], queryFn: () => api.get<ToolOut[]>("/tools") });
}

export function useCreateConnector() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      type: string;
      name: string;
      config: Record<string, unknown>;
      secret_ref: string | null;
    }) => api.post<ConnectorOut>("/connectors", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors"] }),
  });
}

export function useWorkflows() {
  return useQuery({ queryKey: ["workflows"], queryFn: () => api.get<WorkflowOut[]>("/workflows") });
}

export function useWorkflow(id: string) {
  return useQuery({
    queryKey: ["workflow", id],
    queryFn: () => api.get<WorkflowDetailOut>(`/workflows/${id}`),
    enabled: Boolean(id),
  });
}

export function useCreatePlan() {
  return useMutation({
    mutationFn: (prompt: string) => api.post<PlanProposalOut>("/plans", { prompt }),
  });
}

export function useMaterialize() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (proposalId: string) =>
      api.post<MaterializeOut>(`/plans/${proposalId}/materialize`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["workflows"] }),
  });
}

export function useRuns(workflowId?: string) {
  const path = workflowId ? `/runs?workflow_id=${workflowId}` : "/runs";
  return useQuery({
    queryKey: ["runs", workflowId ?? "all"],
    queryFn: () => api.get<RunOut[]>(path),
    refetchInterval: RUN_POLL_MS,
  });
}

export function useRun(id: string) {
  return useQuery({
    queryKey: ["run", id],
    queryFn: () => api.get<RunOut>(`/runs/${id}`),
    enabled: Boolean(id),
    refetchInterval: (query) =>
      query.state.data && TERMINAL.has(query.state.data.status) ? false : RUN_POLL_MS,
  });
}

export function useRunSteps(id: string) {
  return useQuery({
    queryKey: ["run", id, "steps"],
    queryFn: () => api.get<StepRunOut[]>(`/runs/${id}/steps`),
    enabled: Boolean(id),
    refetchInterval: RUN_POLL_MS,
  });
}

export function useRunActions(id: string) {
  return useQuery({
    queryKey: ["run", id, "actions"],
    queryFn: () => api.get<ExternalActionOut[]>(`/runs/${id}/actions`),
    enabled: Boolean(id),
    refetchInterval: RUN_POLL_MS,
  });
}

export function useCreateRun(workflowId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (idempotencyKey: string) =>
      api.post<RunCreateOut>(`/workflows/${workflowId}/runs`, undefined, idempotencyKey),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["runs"] }),
  });
}

/**
 * "Run now" with a stable Idempotency-Key per logical user action (M10 change #3):
 * one key is minted per action and REUSED across double-clicks and retries of an
 * ambiguous/failed attempt, so the backend creates exactly one durable run. The
 * key rotates ONLY after a confirmed success — never merely because a request was
 * retried.
 */
export function useRunNow(workflowId: string): {
  trigger: () => Promise<RunCreateOut>;
  currentKey: () => string;
  isPending: boolean;
  error: unknown;
} {
  const create = useCreateRun(workflowId);
  const keyRef = useRef<string>(crypto.randomUUID());

  const trigger = useCallback(async () => {
    const key = keyRef.current; // reused on retry of the same logical action
    const result = await create.mutateAsync(key); // throws on failure -> no rotation
    keyRef.current = crypto.randomUUID(); // rotate only after success
    return result;
  }, [create]);

  return {
    trigger,
    currentKey: () => keyRef.current,
    isPending: create.isPending,
    error: create.error,
  };
}

export function useApprovals() {
  return useQuery({
    queryKey: ["approvals"],
    queryFn: () => api.get<ApprovalOut[]>("/approvals"),
    refetchInterval: APPROVALS_POLL_MS,
  });
}

export function useDecideApproval() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "approve" | "reject" }) =>
      api.post<ApprovalDecisionOut>(`/approvals/${id}/${decision}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["approvals"] }),
  });
}

export function useSchedules() {
  return useQuery({
    queryKey: ["schedules"],
    queryFn: () => api.get<ScheduleOut[]>("/schedules"),
    refetchInterval: SCHEDULES_POLL_MS,
  });
}

export function useCreateSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      workflow_id: string;
      timezone: string;
      frequency: string;
      minute: number;
      hour: number | null;
      day_of_week: number | null;
    }) => api.post<ScheduleOut>("/schedules", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules"] }),
  });
}

export function useUpdateSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      api.patch<ScheduleOut>(`/schedules/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules"] }),
  });
}

// --- Members & invitations (M11.5 P3A) ------------------------------------

export function useMembers() {
  return useQuery({ queryKey: ["members"], queryFn: () => api.get<MemberOut[]>("/members") });
}

export function useChangeMemberRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: MemberRole }) =>
      api.patch<MemberOut>(`/members/${userId}`, { role }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["members"] }),
  });
}

export function useRemoveMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) => api.del<void>(`/members/${userId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["members"] }),
  });
}

// Invitation listing is admin/owner-only in the UI; `enabled` keeps a plain
// member from firing the request (mirrors the `enabled` convention above).
export function useInvitations(enabled = true) {
  return useQuery({
    queryKey: ["invitations"],
    queryFn: () => api.get<InvitationOut[]>("/invitations"),
    enabled,
  });
}

export function useCreateInvitation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { email: string; role: "admin" | "member" }) =>
      api.post<InvitationCreatedOut>("/invitations", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["invitations"] }),
  });
}

export function useRevokeInvitation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post<void>(`/invitations/${id}/revoke`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["invitations"] }),
  });
}

export function useAcceptInvitation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (token: string) =>
      api.post<InvitationAcceptedOut>("/invitations/accept", { token }),
    // Accepting creates a fresh membership → the caller's workspace list changes.
    onSuccess: () => qc.invalidateQueries({ queryKey: ["workspaces"] }),
  });
}
