import type { NextConfig } from "next";
import { buildContentSecurityPolicy } from "./src/lib/csp";

// Standalone output so the production image is a small self-contained server.
// A strict Content-Security-Policy is applied to all routes (M10 change #10).
// connect-src allows the browser to reach the configured Supabase Auth origin
// (derived from NEXT_PUBLIC_SUPABASE_URL at build time) and nothing else — no
// wildcards, no inline scripts.
const csp = buildContentSecurityPolicy(process.env.NEXT_PUBLIC_SUPABASE_URL);

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
      },
    ];
  },
};

export default nextConfig;
