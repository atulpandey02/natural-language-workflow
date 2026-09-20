import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "./providers";

// Render dynamically per request so the per-request CSP nonce set in proxy.ts is
// applied to Next's inline bootstrap/hydration scripts (a statically prerendered
// page cannot carry a per-request nonce). Authenticated, tenant-specific pages
// are no-store anyway, so there is no caching benefit lost.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "NLW Console",
  description: "Operate natural-language workflows.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
