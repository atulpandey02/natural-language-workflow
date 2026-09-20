import type { NextConfig } from "next";

// Standalone output so the production image is a small self-contained server.
// The Content-Security-Policy is set per-request in proxy.ts (it needs a
// per-request script nonce); the static, non-nonce security headers live here.
const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
      },
    ];
  },
};

export default nextConfig;
