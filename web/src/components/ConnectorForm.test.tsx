import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ConnectorForm } from "./ConnectorForm";

function renderForm() {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <ConnectorForm />
    </QueryClientProvider>,
  );
}

describe("ConnectorForm secret UX", () => {
  it("accepts only a secret reference and explains secrets are pre-provisioned", () => {
    renderForm();
    expect(screen.getByLabelText(/secret reference/i)).toBeInTheDocument();
    expect(screen.getByText(/pre-provisioned by/i)).toBeInTheDocument();
    // There is no field to enter an actual secret value.
    expect(screen.queryByLabelText(/secret value/i)).toBeNull();
    expect(screen.queryByLabelText(/password/i)).toBeNull();
  });

  it("shows postgres-specific config fields by default", () => {
    renderForm();
    expect(screen.getByLabelText(/host/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/database/i)).toBeInTheDocument();
  });
});
