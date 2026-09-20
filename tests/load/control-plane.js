// M11 capacity scenario A — control-plane read/write mix.
// CAPACITY MODE: run with rate limits raised (see README / staging-validation)
// so this measures the system knee, NOT 429s (correction #7).
import { check, sleep } from "k6";
import { get, post } from "./lib.js";

export const options = {
  scenarios: {
    interactive: {
      executor: "ramping-vus",
      startVUs: 1,
      stages: [
        { duration: "30s", target: 5 }, // ~5 concurrent interactive users (initial target)
        { duration: "1m", target: 5 },
        { duration: "20s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    "http_req_duration{kind:read}": ["p(95)<800"],
    "http_req_duration{kind:plan}": ["p(95)<5000"],
  },
};

export default function () {
  for (const p of ["/workflows", "/runs", "/connectors", "/schedules", "/approvals"]) {
    const r = get(p);
    check(r, { "read 200": (x) => x.status === 200 });
  }
  const plan = post("/plans", { prompt: "Summarize yesterday's failed payments." });
  check(plan, { "plan created": (x) => x.status === 201 });
  sleep(1);
}
