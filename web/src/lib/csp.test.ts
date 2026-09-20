import { describe, expect, it } from "vitest";
import { buildContentSecurityPolicy, supabaseOrigin } from "./csp";

describe("supabaseOrigin", () => {
  it("extracts the origin and ignores invalid/absent URLs", () => {
    expect(supabaseOrigin("http://127.0.0.1:54321")).toBe("http://127.0.0.1:54321");
    expect(supabaseOrigin("https://proj.supabase.co/auth/v1")).toBe("https://proj.supabase.co");
    expect(supabaseOrigin(undefined)).toBeNull();
    expect(supabaseOrigin("not a url")).toBeNull();
  });
});

describe("buildContentSecurityPolicy", () => {
  it("allows connect-src to the configured Supabase origin (E2E)", () => {
    const csp = buildContentSecurityPolicy("http://127.0.0.1:54321");
    expect(csp).toContain("connect-src 'self' http://127.0.0.1:54321");
    // Never a wildcard, and unrelated origins are absent.
    expect(csp).not.toContain("connect-src *");
    expect(csp).not.toContain("*");
    expect(csp).not.toContain("https://evil.example.com");
  });

  it("allows connect-src to the configured Supabase origin (production)", () => {
    const csp = buildContentSecurityPolicy("https://proj.supabase.co");
    expect(csp).toContain("connect-src 'self' https://proj.supabase.co");
  });

  it("falls back to 'self' only when no Supabase URL is configured", () => {
    expect(buildContentSecurityPolicy(undefined)).toContain("connect-src 'self';");
  });

  it("keeps the other hardening directives unchanged", () => {
    const csp = buildContentSecurityPolicy("http://127.0.0.1:54321");
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'self'");
  });

  it("uses a nonce + strict-dynamic (never unsafe-inline) for scripts when given a nonce", () => {
    const csp = buildContentSecurityPolicy("http://127.0.0.1:54321", "abc123");
    expect(csp).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
    // scripts never use unsafe-inline (style-src may, which is fine).
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
    // connect-src still restricted to self + the Supabase origin.
    expect(csp).toContain("connect-src 'self' http://127.0.0.1:54321");
  });

  it("falls back to script-src 'self' when no nonce is provided", () => {
    expect(buildContentSecurityPolicy("http://127.0.0.1:54321")).toContain("script-src 'self';");
  });
});
