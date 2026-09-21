// @vitest-environment node
// Server-side cookie posture: Secure by default, disabled only via COOKIE_SECURE.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SUPABASE_COOKIE_NAME, supabaseCookieOptions } from "./shared";

let saved: string | undefined;
beforeEach(() => {
  saved = process.env.COOKIE_SECURE;
});
afterEach(() => {
  if (saved === undefined) delete process.env.COOKIE_SECURE;
  else process.env.COOKIE_SECURE = saved;
});

describe("supabaseCookieOptions (server)", () => {
  it("pins the cookie name, path=/, and SameSite=Lax", () => {
    const o = supabaseCookieOptions();
    expect(o.name).toBe(SUPABASE_COOKIE_NAME);
    expect(o.path).toBe("/");
    expect(o.sameSite).toBe("lax");
  });

  it("is Secure by default (production/staging is HTTPS)", () => {
    delete process.env.COOKIE_SECURE;
    expect(supabaseCookieOptions().secure).toBe(true);
  });

  it("disables Secure only when COOKIE_SECURE=false (e2e HTTP harness)", () => {
    process.env.COOKIE_SECURE = "false";
    expect(supabaseCookieOptions().secure).toBe(false);
  });
});
