import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ConnectorForm } from "./ConnectorForm";

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn(
    async (_input: string | URL | Request, _init?: RequestInit) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
  );
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => vi.unstubAllGlobals());

function renderForm() {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ConnectorForm />
    </QueryClientProvider>,
  );
}

async function fillSlack(values: Partial<Record<string, string>>) {
  const v = {
    name: "product-slack",
    workspace: "NLW Product Demo",
    channel: "C0123ABCD",
    secret: "SLACK_DEMO_BOT_TOKEN",
    ...values,
  };
  if (v.name) await userEvent.type(screen.getByLabelText("Name"), v.name);
  if (v.workspace) await userEvent.type(screen.getByLabelText("Slack workspace"), v.workspace);
  if (v.channel) await userEvent.type(screen.getByLabelText("Default channel ID"), v.channel);
  if (v.secret) await userEvent.type(screen.getByLabelText("Secret reference"), v.secret);
}

const submit = () => userEvent.click(screen.getByRole("button", { name: "Create connector" }));

describe("ConnectorForm: Slack", () => {
  it("asks for name, workspace, channel ID and a secret reference — never secret material", () => {
    renderForm();
    expect(screen.getByLabelText("Type")).toHaveValue("slack");
    for (const label of ["Name", "Slack workspace", "Default channel ID", "Secret reference"]) {
      expect(screen.getByLabelText(label)).toBeInTheDocument();
    }
    expect(screen.queryByLabelText(/token|webhook|password|secret value/i)).toBeNull();
    expect(screen.getByText(/never asks for, shows or stores the secret itself/)).toBeVisible();
    expect(screen.getByTestId("slack-scope-note")).toHaveTextContent(/Alertmanager/);
  });

  it("shows friendly inline errors and sends nothing when required fields are missing", async () => {
    const fetch = mockFetch(201, {});
    renderForm();
    await submit();
    expect(screen.getByText("Give this connector a name.")).toBeInTheDocument();
    expect(screen.getByText("Enter the Slack workspace's name.")).toBeInTheDocument();
    expect(screen.getByText("Enter the channel ID for the default channel.")).toBeInTheDocument();
    expect(screen.getByText("Enter the secret reference name.")).toBeInTheDocument();
    expect(screen.getByLabelText("Default channel ID")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText("Default channel ID")).toHaveAccessibleDescription(
      /channel ID for the default channel/,
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("explains that a #channel name is not a channel ID", async () => {
    const fetch = mockFetch(201, {});
    renderForm();
    await fillSlack({ channel: "#nlw-product-demo" });
    await submit();
    expect(screen.getByText(/Use the channel ID, not its name/)).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    ["a Slack webhook URL", "https://hooks.slack.com/services/T000/B000/XXXXXXXX"],
    ["a bot token", "xoxb-1234-5678-abcdefghijkl"],
  ])("refuses and clears %s pasted as the secret reference", async (_what, material) => {
    const fetch = mockFetch(201, {});
    const { container } = renderForm();
    await fillSlack({ secret: "" });
    await userEvent.click(screen.getByLabelText("Secret reference"));
    await userEvent.paste(material);
    await submit();
    expect(screen.getByText(/That looks like a credential/)).toBeInTheDocument();
    expect(screen.getByLabelText("Secret reference")).toHaveValue("");
    expect(container.innerHTML).not.toContain(material);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("submits exactly the typed Slack schema", async () => {
    const fetch = mockFetch(201, {
      id: "c1",
      type: "slack",
      name: "product-slack",
      config: {},
      status: "unchecked",
      has_secret: true,
    });
    renderForm();
    await fillSlack({ name: "  product-slack ", secret: "slack_demo_bot_token" });
    await submit();
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    const [url, init] = fetch.mock.calls[0];
    expect(url).toBe("/api/nlw/connectors");
    expect(JSON.parse(String(init?.body))).toEqual({
      type: "slack",
      name: "product-slack",
      config: { workspace_label: "NLW Product Demo", default_channel: "C0123ABCD" },
      secret_ref: "SLACK_DEMO_BOT_TOKEN",
    });
    expect(await screen.findByRole("status")).toHaveTextContent(
      /“product-slack” added. An operator must provision its secret/,
    );
  });

  it("puts a duplicate name on the Name field", async () => {
    mockFetch(409, {
      error: { code: "conflict", message: "a connector with this name already exists" },
    });
    renderForm();
    await fillSlack({});
    await submit();
    expect(
      await screen.findByText("A connector with this name already exists."),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Name")).toHaveAttribute("aria-invalid", "true");
  });

  it("never renders raw Pydantic validation text from the API", async () => {
    const raw =
      "1 validation error for SlackConnectorConfig\ndefault_channel\n  Value error, default_channel must be a canonical Slack channel ID";
    mockFetch(422, { error: { code: "unprocessable_entity", message: raw } });
    const { container } = renderForm();
    await fillSlack({});
    await submit();
    expect(await screen.findByTestId("friendly-error")).toHaveTextContent(
      "Some details need attention",
    );
    expect(container.textContent).not.toMatch(
      /validation error for|SlackConnectorConfig|Value error/,
    );
  });
});

describe("ConnectorForm: other types", () => {
  it("shows postgres fields and validates them", async () => {
    const fetch = mockFetch(201, {});
    renderForm();
    await userEvent.selectOptions(screen.getByLabelText("Type"), "postgres");
    expect(screen.queryByLabelText("Slack workspace")).toBeNull();
    await userEvent.type(screen.getByLabelText("Name"), "warehouse");
    await userEvent.type(screen.getByLabelText("Secret reference"), "PG_MAIN");
    await submit();
    expect(screen.getByText("Enter the host.")).toBeInTheDocument();
    expect(screen.getByText("Enter the database name.")).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not apply Slack rules after switching away from Slack", async () => {
    const fetch = mockFetch(201, {});
    renderForm();
    await userEvent.selectOptions(screen.getByLabelText("Type"), "static");
    await userEvent.type(screen.getByLabelText("Name"), "static-e2e");
    await userEvent.type(screen.getByLabelText("Secret reference"), "STATIC_DEMO");
    await submit();
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    expect(JSON.parse(String(fetch.mock.calls[0][1]?.body))).toEqual({
      type: "static",
      name: "static-e2e",
      config: {},
      secret_ref: "STATIC_DEMO",
    });
  });
});
