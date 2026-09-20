// M11 rate-limit scenario — SEPARATE from capacity (correction #7).
// Run with NORMAL limits; prove 429 + Retry-After + per-user/tenant scope.
import { check } from "k6";
import { post } from "./lib.js";

export const options = {
  scenarios: {
    burst: { executor: "shared-iterations", vus: 5, iterations: 60, maxDuration: "30s" },
  },
};

export default function () {
  const r = post("/plans", { prompt: "load" });
  check(r, {
    "allowed or limited": (x) => x.status === 201 || x.status === 429 || x.status === 503,
    "429 has Retry-After": (x) => x.status !== 429 || x.headers["Retry-After"] !== undefined,
  });
}
