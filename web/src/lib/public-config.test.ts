// @vitest-environment node
// The server module refuses to load in a browser context (its window guard), so
// this suite runs under the node environment where server env is read at runtime.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ENV_KEYS = ["SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVER_URL"];

async function loadServer() {
  vi.resetModules();
  return import("./public-config");
}

let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

describe("getServerPublicConfig", () => {
  it("reads the browser-safe values from runtime env", async () => {
    process.env.SUPABASE_URL = "https://proj.supabase.co";
    process.env.SUPABASE_ANON_KEY = "anon-abc";
    const { getServerPublicConfig } = await loadServer();
    expect(getServerPublicConfig()).toEqual({
      supabaseUrl: "https://proj.supabase.co",
      supabaseAnonKey: "anon-abc",
    });
  });

  it("throws when a required value is missing", async () => {
    process.env.SUPABASE_URL = "https://proj.supabase.co";
    const { getServerPublicConfig } = await loadServer();
    expect(() => getServerPublicConfig()).toThrow(/SUPABASE_ANON_KEY/);
  });
});

describe("getServerSupabaseUrl", () => {
  it("defaults to the public URL", async () => {
    process.env.SUPABASE_URL = "https://proj.supabase.co";
    const { getServerSupabaseUrl } = await loadServer();
    expect(getServerSupabaseUrl()).toBe("https://proj.supabase.co");
  });

  it("prefers SUPABASE_SERVER_URL (server network path to the SAME project)", async () => {
    process.env.SUPABASE_URL = "http://127.0.0.1:54321";
    process.env.SUPABASE_SERVER_URL = "http://host.docker.internal:54321";
    const { getServerSupabaseUrl } = await loadServer();
    expect(getServerSupabaseUrl()).toBe("http://host.docker.internal:54321");
  });
});
