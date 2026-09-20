// Isomorphic (server + browser) definitions for the runtime public config.
//
// The Supabase *public* URL and *anon* key are browser-safe (RLS-protected) but
// must be supplied at RUNTIME, not baked into the build — otherwise one immutable
// web image could not target both a staging and a production Supabase project.
// The server reads them from the environment and injects them into the rendered
// document (see public-config.ts + app/layout.tsx); the browser reads them back
// from that document (see public-config.client.ts). No NEXT_PUBLIC_* is used.

/** The ONLY values allowed to reach the browser as runtime public config. */
export interface PublicConfig {
  supabaseUrl: string;
  supabaseAnonKey: string;
}

/** The id of the inline <script type="application/json"> config data block. */
export const PUBLIC_CONFIG_ELEMENT_ID = "__NLW_PUBLIC_CONFIG__";

// Characters that could otherwise terminate the inline data block or break the
// surrounding HTML/JS parse: `<` (would let a value form `</script>`) and the
// line/paragraph separators U+2028/U+2029 (valid in JSON strings but historically
// break JS parsing). The class is built from char codes so this source stays
// pure-ASCII and cannot itself contain a raw separator.
const UNSAFE_HTML_CHARS = new RegExp(`[<${String.fromCharCode(0x2028, 0x2029)}]`, "g");

function toUnicodeEscape(char: string): string {
  return "\\u" + char.charCodeAt(0).toString(16).padStart(4, "0");
}

/**
 * Serialize the allowlisted public config for embedding in an inline
 * `<script type="application/json">` block. Only `supabaseUrl` and
 * `supabaseAnonKey` are emitted; the result is escaped so no value can terminate
 * the block or inject markup.
 */
export function serializePublicConfig(config: PublicConfig): string {
  const allowlisted: PublicConfig = {
    supabaseUrl: config.supabaseUrl,
    supabaseAnonKey: config.supabaseAnonKey,
  };
  return JSON.stringify(allowlisted).replace(UNSAFE_HTML_CHARS, toUnicodeEscape);
}
