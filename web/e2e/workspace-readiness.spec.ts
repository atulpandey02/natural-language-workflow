import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test, expect, type Page } from "@playwright/test";
import {
  E2E_PRIMARY_WORKSPACE,
  E2E_SECONDARY_WORKSPACE,
  waitForWorkspaceOptions,
  workspaceOption,
} from "./helpers";

// Deterministic coverage for the workspace-switcher readiness race (no live
// stack needed). The synthetic page mirrors WorkspaceSwitcher: a placeholder
// while the workspaces query loads, then a <select aria-label="Select
// workspace"> whose options read "<name> (<role>)". Timings are controlled, so
// nothing depends on a random slow run. Synthetic identities only.

const EXPECTED = [E2E_PRIMARY_WORKSPACE, E2E_SECONDARY_WORKSPACE] as const;

type Phase = { at: number; workspaces: string[] | null };

/** Render a switcher that changes over time: null = still loading (placeholder). */
async function switcherPage(page: Page, phases: Phase[]): Promise<void> {
  await page.setContent(`<main><div id="slot"></div></main>
<script>
  const phases = ${JSON.stringify(phases)};
  function render(workspaces) {
    const slot = document.getElementById("slot");
    if (workspaces === null) { slot.innerHTML = '<span class="muted">workspace…</span>'; return; }
    const options = workspaces
      .map((n, i) => '<option value="ws-' + i + '">' + n + ' (owner)</option>').join("");
    slot.innerHTML = '<label>Workspace <select aria-label="Select workspace">' + options + '</select></label>';
  }
  for (const p of phases) setTimeout(() => render(p.workspaces), p.at);
</script>`);
}

test.describe("workspace switcher readiness", () => {
  test("reproduction: a one-shot option read sees no workspaces while the list loads", async ({
    page,
  }) => {
    // Exactly what the old switch test did: wait only for unrelated content,
    // then read the options once. locator.all() does not wait, so it sees the
    // loading placeholder and zero options although both workspaces arrive.
    await switcherPage(page, [
      { at: 0, workspaces: null },
      { at: 700, workspaces: [...EXPECTED] },
    ]);
    const premature = await page
      .getByLabel(/select workspace/i)
      .locator("option")
      .all();
    expect(premature.length).toBe(0);
    // The real final state does contain both workspaces.
    await waitForWorkspaceOptions(page, EXPECTED);
  });

  test("does not return while only one expected workspace is listed", async ({ page }) => {
    await switcherPage(page, [
      { at: 0, workspaces: null },
      { at: 150, workspaces: [E2E_PRIMARY_WORKSPACE] },
      { at: 900, workspaces: [...EXPECTED] },
    ]);
    const switcher = await waitForWorkspaceOptions(page, EXPECTED);
    // At the instant it returns (non-waiting reads), BOTH identities are present:
    // it did not stop at the first one.
    expect(await switcher.locator("option").count()).toBe(2);
    expect(await workspaceOption(switcher, E2E_SECONDARY_WORKSPACE).count()).toBe(1);
  });

  test("succeeds once both expected workspaces appear after the placeholder", async ({ page }) => {
    await switcherPage(page, [
      { at: 0, workspaces: null },
      { at: 600, workspaces: [E2E_SECONDARY_WORKSPACE, E2E_PRIMARY_WORKSPACE] },
    ]);
    const switcher = await waitForWorkspaceOptions(page, EXPECTED);
    const value = await workspaceOption(switcher, E2E_SECONDARY_WORKSPACE).getAttribute("value");
    expect(value).toBe("ws-0"); // selected by identity, whatever the order
  });

  test("an unexpected or look-alike workspace never satisfies readiness", async ({ page }) => {
    await switcherPage(page, [
      {
        at: 0,
        // Exactly two options: the primary and a look-alike of the secondary.
        workspaces: [E2E_PRIMARY_WORKSPACE, `${E2E_SECONDARY_WORKSPACE} 2`],
      },
    ]);
    const error = await waitForWorkspaceOptions(page, EXPECTED, { timeout: 1200 }).then(
      () => null,
      (e: Error) => e,
    );
    expect(error, "two options, one a look-alike, must not satisfy readiness").not.toBeNull();
    expect(error?.message).toContain(`expected workspace option "${E2E_SECONDARY_WORKSPACE}"`);
  });

  test("fails, naming the missing workspace and nothing secret, if it never appears", async ({
    page,
  }) => {
    await switcherPage(page, [
      { at: 0, workspaces: null },
      { at: 100, workspaces: [E2E_PRIMARY_WORKSPACE] },
    ]);
    const error = await waitForWorkspaceOptions(page, EXPECTED, { timeout: 1200 }).then(
      () => null,
      (e: Error) => e,
    );
    expect(error).not.toBeNull();
    const message = error?.message ?? "";
    expect(message).toContain(`expected workspace option "${E2E_SECONDARY_WORKSPACE}"`);
    for (const secret of [process.env.E2E_ADMIN_PASSWORD, process.env.E2E_MEMBER_PASSWORD]) {
      if (secret) expect(message).not.toContain(secret);
    }
    expect(message).not.toMatch(/cookie|bearer|authorization|nlw_ws=/i);
  });

  test("fails if the switcher itself never renders", async ({ page }) => {
    await switcherPage(page, [{ at: 0, workspaces: null }]);
    const error = await waitForWorkspaceOptions(page, EXPECTED, { timeout: 800 }).then(
      () => null,
      (e: Error) => e,
    );
    expect(error?.message).toContain("workspace switcher");
  });
});

test.describe("switch-test contract", () => {
  const read = (file: string) => readFileSync(join(dirname(test.info().file), file), "utf8");

  test("the switch test waits for both seeded workspaces and keeps its tenant assertions", () => {
    const spec = read("guards.spec.ts");
    // Whitespace-normalized so formatting cannot hide or fake a match.
    const body = spec
      .slice(spec.indexOf("switching workspace does not show stale"))
      .replace(/\s+/g, " ")
      .replace(/\( /g, "(")
      .replace(/,? \)/g, ")")
      .replace(/\[ /g, "[")
      .replace(/,? \]/g, "]");
    // Readiness by identity, then an identity-based switch.
    expect(body).toContain(
      "waitForWorkspaceOptions(page, [E2E_PRIMARY_WORKSPACE, E2E_SECONDARY_WORKSPACE])",
    );
    expect(body).toContain("workspaceOption(switcher, E2E_SECONDARY_WORKSPACE)");
    expect(body).not.toMatch(/\.all\(\)|options\.length|selectOption\(\{\s*index/);
    expect(body).not.toMatch(/waitForTimeout|setTimeout|sleep/);
    // Tenant isolation: the previous tenant's workflow must NOT be shown.
    expect(body).toContain(
      'await expect(page.getByRole("link", { name: "E2E Seeded Workflow" })).toHaveCount(0);',
    );
    expect(body).toContain(
      'await expect(page.getByRole("heading", { name: "Workflows" })).toBeVisible();',
    );
  });

  test("the expected workspace names are the ones the seed creates", () => {
    const seed = read("seed.mjs");
    expect(seed).toContain(`createWorkspace(adminToken, "${E2E_PRIMARY_WORKSPACE}")`);
    expect(seed).toContain(`createWorkspace(adminToken, "${E2E_SECONDARY_WORKSPACE}")`);
  });
});
