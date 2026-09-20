# Load tests (k6)

Capacity and rate-limit are SEPARATE (M11 correction #7).

- `control-plane.js` — capacity scenario A. Run with rate limits RAISED so it
  measures the system knee, not 429s.
- `rate-limit.js` — run with NORMAL limits; proves 429 + Retry-After.
- `lib.js` — shared client; reads `K6_BASE_URL`, `K6_TOKEN`, `K6_WORKSPACE`.

Run (Docker):

    docker run --rm --network host \
      -e K6_BASE_URL=http://127.0.0.1:8000 -e K6_TOKEN=<jwt> -e K6_WORKSPACE=<uuid> \
      -v "$PWD/tests/load:/scripts" grafana/k6:0.54.0 run /scripts/control-plane.js

The staging-validation workflow raises limits for the capacity phase and restarts
the API with normal limits for the rate-limit phase.
