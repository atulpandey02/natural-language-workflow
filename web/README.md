# NLW Console (frontend, M10)

Next.js 16 (App Router) + TypeScript. The browser talks only to this app's
same-origin **BFF** (`/api/nlw/*`), which resolves the Supabase session and
injects `Authorization` + `X-Workspace-Id` server-side before calling the
internal FastAPI. Access tokens never touch browser storage. See
[ADR-019](../docs/adr/ADR-019-frontend-architecture.md).

## Configure

Copy `.env.example` to `.env.local`:

- `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` — browser-safe.
- `NLW_API_URL` — internal FastAPI base URL (server-only).
- `WORKSPACE_COOKIE_SECRET` — signs the workspace-selection cookie (server-only).

A real Supabase project (or local Supabase) is required for auth.

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
