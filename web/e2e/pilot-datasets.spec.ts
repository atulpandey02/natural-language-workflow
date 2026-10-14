import { test, expect, type Page } from "@playwright/test";
import { env, requireEnv, signIn } from "./helpers";

// Harness-only (tests/integration/test_pilot_dataset_browser.py): a real API,
// Redis queue and ingest runtime behind the production web build. Synthetic
// data only. Waits are on visible state; the only explicit bound is INGEST_MS,
// the ceiling for the real ingest runtime to settle a small file.
const INGEST_MS = 30_000;
const MAX_BYTES = Number(process.env.E2E_DATASET_MAX_BYTES ?? "0");
const other = {
  email: process.env.E2E_OTHER_EMAIL ?? "",
  password: process.env.E2E_OTHER_PASSWORD ?? "",
};

// Values that must never reach the page: cell contents, and extremes the
// profile-2 contract still carries (min/max/mean) but the page must drop.
const SENTINELS = ["SENTINEL-CELL-7731", "98765.43", "24680.13", "ana@example.test"];
const ORDERS =
  "region,amount,contact,note\n" +
  "North,98765.43,ana@example.test,SENTINEL-CELL-7731\n" +
  "South,24680.13,ben@example.test,plain\n" +
  "North,500,cy@example.test,plain\n";
const MALFORMED = "region,amount\nNorth,1,unexpected\n";

test.describe.configure({ mode: "serial" });
test.beforeEach(() =>
  requireEnv(
    process.env.E2E_PILOT === "1",
    "the dataset journey runs only in the pilot harness (E2E_PILOT=1)",
  ),
);

let journeyDataset = "";
let edgeDataset = "";

function csv(name: string, body: string) {
  return { name, mimeType: "text/csv", buffer: Buffer.from(body) };
}

async function createDataset(page: Page, name: string): Promise<string> {
  await page.goto("/datasets");
  await page.getByLabel("Name", { exact: true }).fill(name);
  await page.getByRole("button", { name: "Create dataset" }).click();
  await page.getByRole("link", { name: "Open it" }).click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const id = new URL(page.url()).pathname.split("/").pop() ?? "";
  expect(id).toMatch(/^[0-9a-f-]{36}$/);
  return id;
}

async function upload(page: Page, name: string, body: string) {
  await page.getByLabel("CSV file").setInputFiles(csv(name, body));
  // Keyboard activation: the control is a real, focusable button.
  await page.getByRole("button", { name: "Upload", exact: true }).press("Enter");
}

const state = (page: Page) => page.getByTestId("version-state");

async function expectNoValues(page: Page) {
  const html = await page.content();
  for (const s of SENTINELS) expect(html).not.toContain(s);
  for (const s of ["storage_key", "source.csv", "dataset_ingest", "content_sha256", "Traceback"])
    expect(html).not.toContain(s);
}

test("admin: create, upload, ingest, profile, confirm, activate, delete", async ({ page }) => {
  requireEnv(Boolean(env.adminEmail && MAX_BYTES), "dataset harness env is not set");
  await signIn(page, env.adminEmail, env.adminPassword);
  await page.goto("/datasets");
  await expect(page.getByRole("heading", { level: 1, name: "Datasets" })).toBeVisible();
  journeyDataset = await createDataset(page, "Synthetic orders");

  await expect(page.getByText(/Maximum size: 4\.1 KB/)).toBeVisible();
  await upload(page, "orders.csv", ORDERS);
  await expect(page.getByTestId("upload-status")).toHaveText(
    "orders.csv uploaded. Processing is queued.",
  );
  await expect(page).toHaveURL(/\?version=[0-9a-f-]{36}$/);

  // A reload during processing returns to the same version and keeps polling.
  await page.reload();
  await expect(state(page)).toHaveText("Profiled", { timeout: INGEST_MS });

  const profile = page.getByTestId("profile");
  await expect(profile.getByRole("cell", { name: "amount" })).toBeVisible();
  await expect(profile.getByText("May contain email addresses")).toBeVisible();
  await expectNoValues(page);

  const form = page.getByTestId("semantics-form");
  await expect(form.getByLabel("Meaning of contact")).toHaveValue("contact");
  await expect(form.getByLabel("Role of contact")).toHaveValue("identifier");
  await form.getByRole("button", { name: "Confirm column meanings" }).click();
  await expect(form.getByText("Column meanings confirmed (revision 1).")).toBeVisible();
  await expect(state(page)).toHaveText("Ready to activate");

  await page.getByRole("button", { name: "Activate this version" }).click();
  await expect(state(page)).toHaveText("Active");

  await page.getByRole("button", { name: "Delete this version" }).click();
  const confirm = page.getByRole("button", { name: "Request deletion", exact: true });
  await expect(confirm).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(state(page)).toHaveText("Deletion requested");
  await expect(page.getByTestId("version-status")).toContainText("does not confirm that removal");

  await page.getByRole("button", { name: "Delete this dataset" }).click();
  await page.getByRole("button", { name: "Request dataset deletion" }).click();
  await expect(page.getByTestId("dataset-deleting")).toContainText("does not confirm that removal");
  await expect(page.getByText("Upload a new version")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText(/\bpurged\b|permanently deleted/i);
});

test("admin: oversized, malformed, lost message and broker outage", async ({ page }) => {
  requireEnv(Boolean(env.adminEmail && MAX_BYTES), "dataset harness env is not set");
  await signIn(page, env.adminEmail, env.adminPassword);
  edgeDataset = await createDataset(page, "Synthetic edge cases");

  // Oversized: refused in the browser; no initiation and no body is sent.
  const writes: string[] = [];
  page.on("request", (r) => {
    if (r.method() !== "GET" && r.url().includes("/api/nlw/datasets/")) writes.push(r.url());
  });
  await page
    .getByLabel("CSV file")
    .setInputFiles(csv("oversized.csv", "a\n" + "x".repeat(MAX_BYTES)));
  await expect(page.getByRole("alert").filter({ hasText: "the maximum is" })).toContainText(
    `the maximum is ${MAX_BYTES} bytes`,
  );
  await expect(page.getByRole("button", { name: "Upload", exact: true })).toBeDisabled();
  expect(writes).toEqual([]);
  // The BFF refuses an over-limit declared length before forwarding it.
  const direct = await page.request.put(
    `/api/nlw/datasets/${edgeDataset}/versions/${crypto.randomUUID()}/content`,
    {
      headers: { "Content-Type": "text/csv", Origin: new URL(page.url()).origin },
      data: Buffer.alloc(MAX_BYTES + 1, 0x61),
    },
  );
  expect(direct.status()).toBe(413);

  // Malformed: accepted for processing, then refused by the ingest runtime.
  await upload(page, "malformed.csv", MALFORMED);
  await expect(state(page)).toHaveText("Rejected", { timeout: INGEST_MS });
  await expect(page.getByTestId("version-status")).toContainText("different number of columns");

  // Lost message: stored and committed, but the queue never delivers it.
  await upload(page, "lost-queue.csv", ORDERS);
  await expect(page.getByTestId("upload-status")).toHaveText(
    "lost-queue.csv uploaded. Processing is queued.",
  );
  await expect(state(page)).toHaveText("Queued");
  await page.getByRole("button", { name: "Request processing again" }).click();
  await expect(state(page)).toHaveText("Profiled", { timeout: INGEST_MS });

  // Broker outage: the API says the stored file was not queued (503).
  await upload(page, "broker-down.csv", ORDERS);
  await expect(page.getByTestId("upload-outcome")).toContainText(
    "Uploaded, but processing was not queued",
  );
  await expect(state(page)).toHaveText("Processing not queued");
  await page.getByRole("button", { name: "Request processing again" }).click();
  await expect(state(page)).toHaveText("Profiled", { timeout: INGEST_MS });
  await expectNoValues(page);
});

test("member: sees datasets but cannot create, upload or review", async ({ page }) => {
  requireEnv(Boolean(env.memberEmail && edgeDataset), "member or dataset missing");
  await signIn(page, env.memberEmail, env.memberPassword);
  await page.goto("/datasets");
  await expect(page.getByRole("link", { name: "Synthetic edge cases" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create dataset" })).toHaveCount(0);
  await page.goto(`/datasets/${edgeDataset}`);
  await expect(
    page.getByText("An admin or owner uploads files and manages versions."),
  ).toBeVisible();
  await expect(page.getByLabel("CSV file")).toHaveCount(0);
  const origin = new URL(page.url()).origin;
  const create = await page.request.post("/api/nlw/datasets", {
    headers: { Origin: origin },
    data: { name: "Not allowed" },
  });
  expect(create.status()).toBe(403);
  const initiate = await page.request.post(`/api/nlw/datasets/${edgeDataset}/versions`, {
    headers: { Origin: origin, "Idempotency-Key": crypto.randomUUID() },
    data: { original_filename: "m.csv", declared_size_bytes: 10 },
  });
  expect(initiate.status()).toBe(403);
});

test("another tenant: the dataset does not exist for them", async ({ page }) => {
  requireEnv(Boolean(other.email && edgeDataset), "other tenant or dataset missing");
  await signIn(page, other.email, other.password);
  await page.goto(`/datasets/${edgeDataset}`);
  await expect(page.getByTestId("dataset-gone")).toContainText("does not exist in this workspace");
  const read = await page.request.get(`/api/nlw/datasets/${edgeDataset}`);
  expect(read.status()).toBe(404);
  const versions = await page.request.get(`/api/nlw/datasets/${edgeDataset}/versions`);
  expect(versions.status()).toBe(404);
  await page.goto("/datasets");
  await expect(page.getByRole("link", { name: "Synthetic edge cases" })).toHaveCount(0);
});
