import { describe, expect, it } from "vitest";
import { serializePublicConfig, type PublicConfig } from "./public-config-shared";

const LS = String.fromCharCode(0x2028); // line separator
const PS = String.fromCharCode(0x2029); // paragraph separator

describe("serializePublicConfig", () => {
  it("emits ONLY the allowlisted public fields", () => {
    const withExtras = {
      supabaseUrl: "https://proj.supabase.co",
      supabaseAnonKey: "anon-abc",
      // Anything else must never be serialized, even if present on the object.
      serviceRoleKey: "SERVICE_ROLE_SHOULD_NOT_LEAK",
      databaseUrl: "postgres://secret",
    } as unknown as PublicConfig;
    const json = serializePublicConfig(withExtras);
    expect(JSON.parse(json)).toEqual({
      supabaseUrl: "https://proj.supabase.co",
      supabaseAnonKey: "anon-abc",
    });
    expect(json).not.toContain("SERVICE_ROLE_SHOULD_NOT_LEAK");
    expect(json).not.toContain("databaseUrl");
  });

  it("escapes < so a value cannot terminate the <script> data block", () => {
    const json = serializePublicConfig({
      supabaseUrl: "https://proj.supabase.co",
      supabaseAnonKey: "</script><script>alert(1)</script>",
    });
    expect(json).not.toContain("</script>");
    expect(json).not.toContain("<");
    expect(json).toContain("\\u003c");
    // Still valid JSON that round-trips to the original value.
    expect(JSON.parse(json).supabaseAnonKey).toBe("</script><script>alert(1)</script>");
  });

  it("escapes U+2028 and U+2029", () => {
    const value = `a${LS}b${PS}c`;
    const json = serializePublicConfig({
      supabaseUrl: "https://proj.supabase.co",
      supabaseAnonKey: value,
    });
    expect(json).not.toContain(LS);
    expect(json).not.toContain(PS);
    expect(json).toContain("\\u2028");
    expect(json).toContain("\\u2029");
    expect(JSON.parse(json).supabaseAnonKey).toBe(value);
  });
});
