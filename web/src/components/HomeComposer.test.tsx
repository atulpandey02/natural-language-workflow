import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const push = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));

import { HomeComposer } from "./HomeComposer";
import { takeDraftQuestion } from "@/lib/draft-question";

afterEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
});

describe("HomeComposer", () => {
  it("hands the question to the analysis composer without putting it in the URL", async () => {
    render(<HomeComposer />);
    const ask = screen.getByRole("button", { name: /Prepare plan/ });
    expect(ask).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Your question"), "Which regions grew?");
    await userEvent.click(ask);
    expect(push).toHaveBeenCalledWith("/workflows/new");
    expect(takeDraftQuestion()).toBe("Which regions grew?");
    expect(takeDraftQuestion()).toBeNull(); // used once
  });

  it("offers Sales and Support samples and marks Staffing as unavailable", () => {
    render(<HomeComposer />);
    expect(screen.getByRole("link", { name: /Sales performance/ })).toHaveAttribute(
      "href",
      "/workflows/new?dataset=sales-v1",
    );
    expect(screen.getByRole("link", { name: /Support operations/ })).toHaveAttribute(
      "href",
      "/workflows/new?dataset=support-v1",
    );
    expect(screen.queryByRole("link", { name: /Staffing/ })).toBeNull();
    expect(screen.getByText(/Not in this pilot/)).toBeVisible();
  });
});
