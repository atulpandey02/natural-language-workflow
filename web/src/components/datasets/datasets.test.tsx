import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import type { ReactNode } from "react";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// A fake API behind the real hooks: every read/write is answered by path.
vi.mock("@/lib/api/client", () => ({
  api: { get: vi.fn(), post: vi.fn(), del: vi.fn() },
}));
vi.mock("@/lib/api/upload", () => ({ uploadContent: vi.fn(), fetchUploadLimit: vi.fn() }));
vi.mock("@/lib/api/hooks", () => ({ useCurrentWorkspace: vi.fn() }));
vi.mock("@/components/AppShell", () => ({
  AppShell: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));
const replace = vi.fn();
let search = "";
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace }),
  usePathname: () => `/datasets/${D}`,
  useSearchParams: () => new URLSearchParams(search),
}));

import { api } from "@/lib/api/client";
import { fetchUploadLimit, uploadContent } from "@/lib/api/upload";
import { useCurrentWorkspace } from "@/lib/api/hooks";
import { ApiError } from "@/lib/errors";
import { markNotQueued, savePending } from "@/lib/datasets";
import { PROFILE, version } from "@/lib/datasets.fixtures";
import type { DatasetOut, DatasetVersionOut } from "@/lib/api/types";
import DatasetsPage from "@/app/datasets/page";
import { DatasetDetail } from "./DatasetDetail";

const D = "22222222-2222-4222-8222-222222222222";
const V = "11111111-1111-4111-8111-111111111111";
const get = api.get as unknown as Mock;
const post = api.post as unknown as Mock;
const del = api.del as unknown as Mock;
const send = uploadContent as unknown as Mock;

const dataset: DatasetOut = {
  id: D,
  name: "Synthetic orders",
  description: null,
  status: "ACTIVE",
  active_version_id: null,
  version_count: 1,
  created_by: "u",
  created_at: "2026-10-14T10:00:00Z",
  updated_at: "2026-10-14T10:00:00Z",
  deletion_requested_at: null,
};

const notFound = (code: string) => new ApiError({ status: 404, code, message: "x" });

interface World {
  role: string;
  dataset: DatasetOut | ApiError;
  versions: DatasetVersionOut[];
  version: DatasetVersionOut | ApiError;
  profile: unknown;
  revisions: unknown[];
}
let world: World;

function serve() {
  get.mockImplementation(async (path: string) => {
    const answer = (() => {
      if (path === "/datasets") return [dataset];
      if (path === `/datasets/${D}`) return world.dataset;
      if (path === `/datasets/${D}/versions`) return world.versions;
      if (path === `/datasets/${D}/versions/${V}`) return world.version;
      if (path.endsWith("/profile")) return world.profile;
      if (path.endsWith("/semantics")) return world.revisions;
      return notFound("not_found");
    })();
    if (answer instanceof Error) throw answer;
    return answer;
  });
  (useCurrentWorkspace as unknown as Mock).mockImplementation(() => ({
    data: { tenant_id: "t", role: world.role },
  }));
  (fetchUploadLimit as unknown as Mock).mockResolvedValue(1000);
}

function renderWith(ui: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

const FORBIDDEN_TEXT = [
  "SENTINEL-MIN-901",
  "SENTINEL-MAX-902",
  "903.25",
  "storage_key",
  "versions/t/d/v/source.csv",
  "aaaaaaaa",
  "s3://",
  "dataset_ingest",
  "Traceback",
];
function expectNoLeak() {
  const text = document.body.innerHTML;
  for (const s of FORBIDDEN_TEXT) expect(text).not.toContain(s);
}

beforeEach(() => {
  window.sessionStorage.clear();
  search = "";
  world = {
    role: "admin",
    dataset,
    versions: [],
    version: version(),
    profile: PROFILE,
    revisions: [],
  };
  serve();
});
afterEach(() => vi.clearAllMocks());

describe("Datasets list", () => {
  it("lets an admin create a dataset", async () => {
    post.mockResolvedValue({ ...dataset, id: D, name: "New one" });
    renderWith(<DatasetsPage />);
    expect(await screen.findByRole("link", { name: "Synthetic orders" })).toHaveAttribute(
      "href",
      `/datasets/${D}`,
    );
    await userEvent.type(screen.getByLabelText("Name"), "New one");
    await userEvent.click(screen.getByRole("button", { name: "Create dataset" }));
    expect(post).toHaveBeenCalledWith("/datasets", { name: "New one" });
    expect(await screen.findByText(/Dataset “New one” created/)).toBeInTheDocument();
  });

  it("hides creation from a member and says who can create", async () => {
    world.role = "member";
    renderWith(<DatasetsPage />);
    await screen.findByRole("link", { name: "Synthetic orders" });
    expect(screen.queryByRole("button", { name: "Create dataset" })).toBeNull();
    expect(screen.getByText(/An admin or owner creates datasets/)).toBeInTheDocument();
  });

  it("explains that datasets are off when the API does not mount them", async () => {
    get.mockRejectedValue(notFound("not_found"));
    renderWith(<DatasetsPage />);
    expect(await screen.findByText(/not enabled in this environment/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create dataset" })).toBeNull();
  });
});

describe("Dataset detail: roles and missing resources", () => {
  it("a member sees versions and states but no upload, recovery, profile or deletion", async () => {
    world.role = "member";
    world.versions = [version({ has_content: true })];
    search = `version=${V}`;
    world.version = version({ has_content: true });
    renderWith(<DatasetDetail id={D} />);
    expect(await screen.findByTestId("version-state")).toHaveTextContent("Queued");
    expect(screen.queryByText("Upload a new version")).toBeNull();
    expect(screen.queryByRole("button", { name: /Request processing again/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Delete/ })).toBeNull();
    // Profile and semantics are admin-only in the API: a member never asks.
    expect(get.mock.calls.some(([p]) => String(p).endsWith("/profile"))).toBe(false);
  });

  it("a member never requests the profile of a profiled version", async () => {
    world.role = "member";
    search = `version=${V}`;
    world.version = version({ status: "PROFILED", has_content: true });
    renderWith(<DatasetDetail id={D} />);
    expect(await screen.findByTestId("version-state")).toHaveTextContent("Profiled");
    expect(get.mock.calls.some(([p]) => /\/(profile|semantics)$/.test(String(p)))).toBe(false);
    expect(screen.queryByTestId("profile")).toBeNull();
  });

  it("a foreign or deleted dataset is simply unavailable (404), with no purge claim", async () => {
    world.dataset = notFound("DATASET_NOT_FOUND");
    renderWith(<DatasetDetail id={D} />);
    const gone = await screen.findByTestId("dataset-gone");
    expect(gone).toHaveTextContent(/does not exist in this workspace/);
    expect(document.body.textContent).not.toMatch(/purged|permanently/i);
  });

  it("a foreign or deleted version is unavailable (404)", async () => {
    search = `version=${V}`;
    world.version = notFound("DATASET_VERSION_NOT_FOUND");
    renderWith(<DatasetDetail id={D} />);
    expect(await screen.findByTestId("version-gone")).toHaveTextContent(/does not exist/);
    expect(document.body.textContent).not.toMatch(/purged/i);
  });

  it("ignores a version id that is not a UUID", async () => {
    search = "version=../../admin";
    renderWith(<DatasetDetail id={D} />);
    await screen.findByText("Synthetic orders");
    expect(get.mock.calls.some(([p]) => String(p).includes("admin"))).toBe(false);
  });
});

describe("Upload panel", () => {
  it("shows the maximum and refuses a non-CSV or oversized file before sending", async () => {
    renderWith(<DatasetDetail id={D} />);
    expect(await screen.findByText(/Maximum size: 1 KB/)).toBeInTheDocument();
    const input = screen.getByLabelText("CSV file");
    await userEvent.upload(input, new File(["x".repeat(2000)], "big.csv", { type: "text/csv" }));
    expect(screen.getByRole("alert")).toHaveTextContent(/maximum is 1 KB/);
    expect(screen.getByRole("button", { name: "Upload" })).toBeDisabled();
    await userEvent.upload(input, new File(["a"], "data.xlsx"), { applyAccept: false });
    expect(screen.getByRole("alert")).toHaveTextContent("Choose a .csv file.");
    expect(post).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
  });

  it("uploads by keyboard alone, shows progress and announces the result", async () => {
    let finish: (v: DatasetVersionOut) => void = () => {};
    post.mockResolvedValue(version());
    send.mockImplementation((_d, _v, _f, onProgress) => {
      onProgress({ loaded: 6, total: 12 });
      return new Promise((r) => (finish = r));
    });
    renderWith(<DatasetDetail id={D} />);
    const input = await screen.findByLabelText("CSV file");
    await userEvent.upload(
      input,
      new File(["a,b\n1,2\n3,4\n"], "orders.csv", { type: "text/csv" }),
    );
    const upload = screen.getByRole("button", { name: "Upload" });
    upload.focus();
    await userEvent.keyboard("{Enter}");
    const bar = await screen.findByLabelText("Upload progress");
    expect(bar).toHaveAttribute("value", "6");
    expect(screen.getByText("50%")).toBeInTheDocument();
    expect(screen.getByTestId("upload-status")).toHaveTextContent("Uploading orders.csv.");
    expect(post).toHaveBeenCalledWith(
      `/datasets/${D}/versions`,
      { original_filename: "orders.csv", declared_size_bytes: 12 },
      expect.any(String),
    );
    await act(async () => finish(version({ has_content: true })));
    expect(await screen.findByTestId("upload-status")).toHaveTextContent(
      "orders.csv uploaded. Processing is queued.",
    );
    expect(replace).toHaveBeenCalledWith(`/datasets/${D}?version=${V}`, { scroll: false });
  });

  it.each([
    [new ApiError({ status: 413, code: "CONTENT_TOO_LARGE", message: "x" }), "too large"],
    [new ApiError({ status: 403, code: "forbidden", message: "x" }), "can't upload here"],
    [
      new ApiError({ status: 500, code: "internal_error", message: "Traceback s3://bucket/key" }),
      "Something went wrong",
    ],
  ])("explains a refused upload without internal detail (%#)", async (error, text) => {
    post.mockResolvedValue(version());
    send.mockRejectedValue(error);
    renderWith(<DatasetDetail id={D} />);
    await userEvent.upload(
      await screen.findByLabelText("CSV file"),
      new File(["a\n1\n"], "orders.csv", { type: "text/csv" }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Upload" }));
    expect(await screen.findByTestId("upload-outcome")).toHaveTextContent(new RegExp(text, "i"));
    expectNoLeak();
  });

  it("after a reload mid-upload, explains how to continue the same version", async () => {
    savePending(D, { key: "k1", filename: "orders.csv", size: 12, lastModified: 1, versionId: V });
    renderWith(<DatasetDetail id={D} />);
    expect(await screen.findByTestId("resume-notice")).toHaveTextContent(
      /Choose the same file .* continues the same version/,
    );
  });
});

describe("Version panel", () => {
  beforeEach(() => {
    search = `version=${V}`;
  });

  it("offers safe recovery for a stored file that was not queued, and re-polls", async () => {
    world.version = version({ has_content: true });
    markNotQueued(V, true);
    post.mockResolvedValue(version({ has_content: true }));
    renderWith(<DatasetDetail id={D} />);
    expect(await screen.findByTestId("version-state")).toHaveTextContent("Processing not queued");
    expect(screen.getByTestId("version-status")).toHaveTextContent(/Nothing was lost/);
    await userEvent.click(screen.getByRole("button", { name: "Request processing again" }));
    // The existing re-dispatch endpoint for THIS version: never a new version.
    expect(post).toHaveBeenCalledWith(`/datasets/${D}/versions/${V}/process`);
    expect(post.mock.calls.some(([p]) => p === `/datasets/${D}/versions`)).toBe(false);
    await waitFor(() => expect(screen.getByTestId("version-state")).toHaveTextContent("Queued"));
  });

  it("explains a rejected (malformed) file with a plain reason", async () => {
    world.version = version({ status: "REJECTED", rejection_code: "ROW_WIDTH_MISMATCH" });
    renderWith(<DatasetDetail id={D} />);
    expect(await screen.findByTestId("version-status")).toHaveTextContent(
      /refused.*different number of columns/,
    );
    expect(screen.queryByRole("button", { name: "Request processing again" })).toBeNull();
  });

  it("renders the profile without values or internal fields", async () => {
    world.version = version({ status: "PROFILED", has_content: true });
    renderWith(<DatasetDetail id={D} />);
    const profile = await screen.findByTestId("profile");
    expect(within(profile).getByText("Amount")).toBeInTheDocument();
    expect(within(profile).getByText("May contain email addresses")).toBeInTheDocument();
    expectNoLeak();
  });

  it("proposes column meanings and an admin confirms them", async () => {
    world.version = version({ status: "PROFILED", has_content: true });
    post.mockResolvedValue({
      id: "r1",
      revision_number: 1,
      mapping: {},
      confirmed_by: "u",
      confirmed_at: "",
    });
    renderWith(<DatasetDetail id={D} />);
    const form = await screen.findByTestId("semantics-form");
    expect(within(form).getByLabelText("Meaning of Email")).toHaveValue("contact");
    expect(within(form).getByLabelText("Role of Email")).toHaveValue("identifier");
    await userEvent.click(within(form).getByRole("button", { name: "Confirm column meanings" }));
    const [path, body] = post.mock.calls[0];
    expect(path).toBe(`/datasets/${D}/versions/${V}/semantics`);
    expect(body.columns.map((c: { name: string }) => c.name)).toEqual([
      "region",
      "amount",
      "email",
    ]);
    expect(await within(form).findByText(/confirmed \(revision 1\)/)).toBeInTheDocument();
  });

  it("keeps the confirmation announced after the new revision is fetched", async () => {
    world.version = version({ status: "PROFILED", has_content: true });
    const rev = {
      id: "r1",
      revision_number: 1,
      mapping: { columns: [] },
      confirmed_by: "u",
      confirmed_at: "",
    };
    post.mockImplementation(async () => {
      world.revisions = [rev];
      return rev;
    });
    renderWith(<DatasetDetail id={D} />);
    const form = await screen.findByTestId("semantics-form");
    await userEvent.click(within(form).getByRole("button", { name: "Confirm column meanings" }));
    await waitFor(() =>
      expect(screen.getByTestId("version-state")).toHaveTextContent("Ready to activate"),
    );
    expect(screen.getByTestId("semantics-form")).toHaveTextContent(
      "Column meanings confirmed (revision 1).",
    );
  });

  it("locks analysis of a contact column unless it is an identifier", async () => {
    world.version = version({ status: "PROFILED", has_content: true });
    renderWith(<DatasetDetail id={D} />);
    const form = await screen.findByTestId("semantics-form");
    await userEvent.selectOptions(within(form).getByLabelText("Role of Email"), "attribute");
    const box = within(form).getByLabelText("Allow analysis of Email");
    expect(box).toBeDisabled();
    expect(box).not.toBeChecked();
    expect(within(form).getByText(/only as an identifier/)).toBeInTheDocument();
  });

  it("activates a version whose meanings are confirmed", async () => {
    world.version = version({ status: "PROFILED", has_content: true });
    world.revisions = [
      {
        id: "r1",
        revision_number: 1,
        mapping: { columns: [] },
        confirmed_by: "u",
        confirmed_at: "",
      },
    ];
    post.mockResolvedValue(version({ status: "ACTIVE", has_content: true }));
    renderWith(<DatasetDetail id={D} />);
    await userEvent.click(await screen.findByRole("button", { name: "Activate this version" }));
    expect(post).toHaveBeenCalledWith(`/datasets/${D}/versions/${V}/activate`);
  });

  it("deletion is a two-step request and never claims the file is gone", async () => {
    world.version = version({ status: "ACTIVE", has_content: true });
    del.mockResolvedValue(version({ status: "DELETING", has_content: true }));
    renderWith(<DatasetDetail id={D} />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete this version" }));
    expect(del).not.toHaveBeenCalled();
    const confirm = screen.getByRole("button", { name: "Request deletion" });
    expect(confirm).toHaveFocus();
    expect(screen.getByRole("group")).toHaveTextContent(/does not confirm that removal/);
    world.version = version({ status: "DELETING", has_content: true });
    await userEvent.keyboard("{Enter}");
    expect(del).toHaveBeenCalledWith(`/datasets/${D}/versions/${V}`);
    await waitFor(() =>
      expect(screen.getByTestId("version-state")).toHaveTextContent("Deletion requested"),
    );
    expect(document.body.textContent).not.toMatch(/\bpurged\b|has been removed|permanently/i);
  });

  it("a dataset deletion request disables uploads and says removal is separate", async () => {
    world.dataset = { ...dataset, status: "DELETING" };
    renderWith(<DatasetDetail id={D} />);
    expect(await screen.findByTestId("dataset-deleting")).toHaveTextContent(
      /does not confirm that removal/,
    );
    expect(screen.queryByText("Upload a new version")).toBeNull();
  });
});
