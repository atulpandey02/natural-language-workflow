# NLW Console (frontend, M10)

Next.js 16 (App Router) + TypeScript. The browser talks only to this app's
same-origin **BFF** (`/api/nlw/*`), which resolves the Supabase session and
injects `Authorization` + `X-Workspace-Id` server-side before calling the
internal FastAPI. Access tokens never touch browser storage. See
[ADR-019](../docs/adr/ADR-019-frontend-architecture.md).

## Configure

Copy `.env.example` to `.env.local`:

- `SUPABASE_URL`, `SUPABASE_ANON_KEY` — browser-safe public config, supplied at
  **runtime** (the Next server injects them into the rendered document; no
  `NEXT_PUBLIC_*` is baked into the build, so one image targets any environment).
- `SUPABASE_SERVER_URL` — optional; overrides only how the Next **server** reaches
  the same Supabase project (private DNS / host gateway).
- `NLW_API_URL` — internal FastAPI base URL (server-only).
- `WORKSPACE_COOKIE_SECRET` — signs the workspace-selection cookie (server-only).

A real Supabase project (or local Supabase) is required for auth. Because the
public config is runtime-supplied, the **same** built image + digest is promoted
unchanged from staging to production and pointed at each environment's Supabase
project via these env vars (see the artifact-invariance proof in `scripts/`).

## Develop

```bash
npm install
npm run dev          # http://localhost:3000
npm run lint         # eslint
npm run typecheck    # tsc --noEmit
npm run format:check # prettier
npm test             # vitest (unit/component)
npm run build        # production build (standalone)
npm run e2e          # playwright (requires a seeded live stack; self-skips otherwise)
```

## Docker

Built as a standalone, non-root image (`web/Dockerfile`). In production it runs
internally; Caddy is the only public ingress (`docker-compose.prod.yml`).
