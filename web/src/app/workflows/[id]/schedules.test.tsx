import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock("@/components/AppShell", () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock("@/components/ScheduleForm", () => ({ ScheduleForm: () => null }));
vi.mock("@/lib/api/hooks", () => ({
  useCurrentWorkspace: vi.fn(),
  useRunNow: vi.fn(),
  useRuns: vi.fn(),
  useSchedules: vi.fn(),
  useWorkflow: vi.fn(),
  useWorkflowProvenance: vi.fn(),
}));

import WorkflowDetailPage from "./page";
import {
  useCurrentWorkspace,
  useRunNow,
  useRuns,
  useSchedules,
  useWorkflow,
  useWorkflowProvenance,
} from "@/lib/api/hooks";

const WF_ID = "11111111-2222-3333-4444-555555555555";

function settled<T>(value: T): Promise<T> {
  const p = Promise.resolve(value) as Promise<T> & { status?: string; value?: T };
  p.status = "fulfilled";
  p.value = value;
  return p;
}

const SCHEDULE = {
  id: "s1",
  workflow_id: WF_ID,
  workflow_version_id: "v1",
  timezone: "UTC",
  frequency: "daily",
  minute: 0,
  hour: 9,
  day_of_week: null,
  enabled: true,
  next_run_at: "2026-09-27T09:00:00Z",
  last_scheduled_for: null,
  blocked_reason: "CREATOR_ROLE_INSUFFICIENT",
  blocked_at: "2026-09-26T01:00:00Z",
};

afterEach(() => vi.clearAllMocks());

describe("WorkflowDetailPage schedule cards", () => {
  it("renders an enabled-but-blocked schedule as blocked with a safe explanation", () => {
    (useCurrentWorkspace as unknown as Mock).mockReturnValue({
      data: { tenant_id: "t1", role: "member" },
    });
    (useRunNow as unknown as Mock).mockReturnValue({
      trigger: vi.fn(),
      isPending: false,
      currentKey: () => "k",
    });
    (useRuns as unknown as Mock).mockReturnValue({ isLoading: false, error: null, data: [] });
    (useSchedules as unknown as Mock).mockReturnValue({
      isLoading: false,
      error: null,
      data: [SCHEDULE],
    });
    (useWorkflow as unknown as Mock).mockReturnValue({
      isLoading: false,
      error: null,
      data: {
        id: WF_ID,
        name: "Nightly",
        current_version_id: "v1",
        created_at: "2026-09-26T00:00:00Z",
        current_version: { id: "v1", workflow_id: WF_ID, version: 1, plan: { steps: [] } },
      },
    });
    (useWorkflowProvenance as unknown as Mock).mockReturnValue({
      isLoading: false,
      error: null,
      data: undefined,
    });

    render(<WorkflowDetailPage params={settled({ id: WF_ID })} />);
    expect(screen.getByText("blocked")).toHaveClass("fail");
    expect(screen.queryByText("active")).not.toBeInTheDocument();
    const reason = screen.getByTestId("schedule-blocked-reason");
    expect(reason).toHaveTextContent(/admin or owner role/);
    expect(reason).not.toHaveTextContent("CREATOR_ROLE_INSUFFICIENT");
  });
});
