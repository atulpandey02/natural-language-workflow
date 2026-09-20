// Shared k6 helpers. The load client calls the API directly with a pre-minted
// bearer token + X-Workspace-Id (provided by the seed step) so we measure the
// control plane's own knee. BASE_URL points at the API (internal) or the edge.
import http from "k6/http";

export const BASE_URL = __ENV.K6_BASE_URL || "http://api:8000";
const TOKEN = __ENV.K6_TOKEN || "";
const WORKSPACE = __ENV.K6_WORKSPACE || "";

export function authHeaders() {
  return {
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      "X-Workspace-Id": WORKSPACE,
      "Content-Type": "application/json",
    },
  };
}

export function get(path) {
  return http.get(`${BASE_URL}${path}`, authHeaders());
}

export function post(path, body) {
  return http.post(`${BASE_URL}${path}`, JSON.stringify(body || {}), authHeaders());
}
