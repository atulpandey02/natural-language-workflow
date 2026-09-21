// Browser-side cookie posture: Secure derives from the page protocol (jsdom
// serves http://localhost, so Secure is false here; real production is HTTPS).
import { describe, expect, it } from "vitest";
import { supabaseCookieOptions } from "./shared";

describe("supabaseCookieOptions (browser)", () => {
  it("derives Secure from the page protocol; keeps SameSite=Lax and path=/", () => {
    const o = supabaseCookieOptions();
    expect(window.location.protocol).toBe("http:"); // jsdom default
    expect(o.secure).toBe(false); // would be true on an https page
    expect(o.sameSite).toBe("lax");
    expect(o.path).toBe("/");
  });
});
