import { afterEach, describe, expect, it, vi } from "vitest";
import { PUBLIC_CONFIG_ELEMENT_ID, serializePublicConfig } from "./public-config-shared";

// Fresh module per test so the internal cache does not bleed across cases.
async function loadReader() {
  vi.resetModules();
  return (await import("./public-config.client")).getBrowserPublicConfig;
}

function inject(json: string) {
  const el = document.createElement("script");
  el.id = PUBLIC_CONFIG_ELEMENT_ID;
  el.type = "application/json";
  el.textContent = json;
  document.head.appendChild(el);
}

afterEach(() => {
  document.getElementById(PUBLIC_CONFIG_ELEMENT_ID)?.remove();
});

describe("getBrowserPublicConfig", () => {
  it("reads the runtime config the server injected into the document", async () => {
    inject(
      serializePublicConfig({
        supabaseUrl: "https://proj.supabase.co",
        supabaseAnonKey: "anon-abc",
      }),
    );
    const getBrowserPublicConfig = await loadReader();
    expect(getBrowserPublicConfig()).toEqual({
      supabaseUrl: "https://proj.supabase.co",
      supabaseAnonKey: "anon-abc",
    });
  });

  it("round-trips values containing escaped characters", async () => {
    const value = `a<b${String.fromCharCode(0x2028)}c`;
    inject(
      serializePublicConfig({ supabaseUrl: "https://proj.supabase.co", supabaseAnonKey: value }),
    );
    const getBrowserPublicConfig = await loadReader();
    expect(getBrowserPublicConfig().supabaseAnonKey).toBe(value);
  });

  it("throws (fails loud) when the config block is absent", async () => {
    const getBrowserPublicConfig = await loadReader();
    expect(() => getBrowserPublicConfig()).toThrow(/missing/i);
  });

  it("throws when the config is incomplete", async () => {
    inject(JSON.stringify({ supabaseUrl: "https://proj.supabase.co" }));
    const getBrowserPublicConfig = await loadReader();
    expect(() => getBrowserPublicConfig()).toThrow(/incomplete/i);
  });
});
