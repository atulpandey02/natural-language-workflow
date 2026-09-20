import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { RoleGate, StatusBadge, canApprove } from "./ui";

describe("RoleGate", () => {
  it("renders children only for allowed roles", () => {
    const { rerender } = render(
      <RoleGate role="member" allow={["owner", "admin"]}>
        <button>Admin action</button>
      </RoleGate>,
    );
    expect(screen.queryByText("Admin action")).toBeNull();

    rerender(
      <RoleGate role="admin" allow={["owner", "admin"]}>
        <button>Admin action</button>
      </RoleGate>,
    );
    expect(screen.getByText("Admin action")).toBeInTheDocument();
  });
});

describe("canApprove", () => {
  it("is true only for owner/admin", () => {
    expect(canApprove("owner")).toBe(true);
    expect(canApprove("admin")).toBe(true);
    expect(canApprove("member")).toBe(false);
    expect(canApprove(undefined)).toBe(false);
  });
});

describe("StatusBadge", () => {
  it("renders the status text", () => {
    render(<StatusBadge status="COMPLETED" />);
    expect(screen.getByText("COMPLETED")).toBeInTheDocument();
  });
});
