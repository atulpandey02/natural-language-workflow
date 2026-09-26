import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";

vi.mock("@/components/AppShell", () => ({
  AppShell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock("@/lib/api/hooks", () => ({
  useSchedules: vi.fn(),
  useCurrentWorkspace: vi.fn(),
  useUpdateSchedule: vi.fn(),
}));

import SchedulesPage from "./page";
import { useCurrentWorkspace, useSchedules, useUpdateSchedule } from "@/lib/api/hooks";

const mockSchedules = useSchedules as unknown as Mock;
const mockCurrent = useCurrentWorkspace as unknown as Mock;
const mockUpdate = useUpdateSchedule as unknown as Mock;

const BASE = {
  id: "11111111-2222-3333-4444-555555555555",
  workflow_id: "66666666-7777-8888-9999-000000000000",
  workflow_version_id: "v1",
  timezone: "UTC",
  frequency: "daily",
  minute: 0,
  hour: 9,
  day_of_week: null,
  next_run_at: "2026-09-27T09:00:00Z",
  last_scheduled_for: null,
};

function setup(schedules: object[]): void {
  mockSchedules.mockReturnValue({ isLoading: false, error: null, data: schedules });
  mockCurrent.mockReturnValue({ data: { tenant_id: "t1", role: "admin" } });
  mockUpdate.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null });
}

afterEach(() => vi.clearAllMocks());

describe("SchedulesPage status truthfulness", () => {
  it("shows an enabled but authorization-blocked schedule as BLOCKED, never active", () => {
    setup([
      {
        ...BASE,
        enabled: true,
        blocked_reason: "CREATOR_NOT_A_MEMBER",
        blocked_at: "2026-09-26T01:00:00Z",
      },
    ]);
    render(<SchedulesPage />);
    const badge = screen.getByText("blocked");
    expect(badge).toHaveClass("fail");
    expect(screen.queryByText("active")).not.toBeInTheDocument();
    const reason = screen.getByTestId("schedule-blocked-reason");
    expect(reason).toHaveTextContent(/no longer a member of this workspace/);
    // Raw reason code / internals are not shown to the user.
    expect(reason).not.toHaveTextContent("CREATOR_NOT_A_MEMBER");
  });

  it("shows active for an enabled, unblocked schedule and disabled otherwise", () => {
    setup([
      { ...BASE, id: "a", enabled: true, blocked_reason: null, blocked_at: null },
      { ...BASE, id: "b", enabled: false, blocked_reason: null, blocked_at: null },
    ]);
    render(<SchedulesPage />);
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.getByText("disabled")).toBeInTheDocument();
    expect(screen.queryByText("blocked")).not.toBeInTheDocument();
    expect(screen.queryByTestId("schedule-blocked-reason")).not.toBeInTheDocument();
  });

  it("renders a generic sentence for an unknown reason code (no internals)", () => {
    setup([{ ...BASE, enabled: true, blocked_reason: "SOMETHING_NEW", blocked_at: null }]);
    render(<SchedulesPage />);
    const reason = screen.getByTestId("schedule-blocked-reason");
    expect(reason).toHaveTextContent(/no longer authorized/);
    expect(reason).not.toHaveTextContent("SOMETHING_NEW");
  });
});
