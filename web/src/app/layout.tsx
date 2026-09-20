import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";
import { Providers } from "./providers";
import { getServerPublicConfig } from "@/lib/public-config";
import { PUBLIC_CONFIG_ELEMENT_ID, serializePublicConfig } from "@/lib/public-config-shared";

// Render dynamically per request so the per-request CSP nonce set in proxy.ts is
// applied to Next's inline bootstrap/hydration scripts (a statically prerendered
// page cannot carry a per-request nonce). Authenticated, tenant-specific pages
// are no-store anyway, so there is no caching benefit lost.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "NLW Console",
  description: "Operate natural-language workflows.",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  // Inject the RUNTIME public config (allowlisted, escaped) as a non-executable
  // data block. The browser reads it via getBrowserPublicConfig(); because it is
  // supplied at runtime, one immutable image serves any Supabase project.
  const publicConfigJson = serializePublicConfig(getServerPublicConfig());
  return (
    <html lang="en">
      <head>
        <script
          id={PUBLIC_CONFIG_ELEMENT_ID}
          type="application/json"
          nonce={nonce}
          dangerouslySetInnerHTML={{ __html: publicConfigJson }}
        />
      </head>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
