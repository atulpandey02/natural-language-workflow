# Next.js frontend (standalone output). Internal-only container; the Caddy
# reverse proxy is the sole public ingress (M10 change #11). Runs as non-root.
#
# Base image: an explicit Node patch version on an explicit Debian release, the
# SAME in every stage so the native binaries resolved by `npm ci` (Next SWC,
# sharp) are built against the glibc they run on. Never the floating
# `node:22-slim` tag: it silently tracks Debian 12 "bookworm", whose perl-base
# (5.36.0-7+deb12u3) carries CVE-2026-13221, CVE-2026-42496 and CVE-2026-8376
# (CRITICAL). Changing the base is a reviewed change, guarded by
# tests/unit/test_web_image_base.py.
FROM node:22.23.3-trixie-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22.23.3-trixie-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# No public config is baked at build time: the browser-safe Supabase URL + anon
# key are supplied at RUNTIME (server-injected into the document) so one immutable
# image targets any environment. Server-only env is likewise provided at runtime.
RUN npm run build

FROM node:22.23.3-trixie-slim AS runner
ARG NLW_GIT_SHA=unknown
LABEL org.opencontainers.image.revision=${NLW_GIT_SHA}
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
# The standalone runtime only runs `node server.js` — it never uses npm/npx/
# corepack. Remove them so the base image's bundled npm toolchain (which ships a
# vulnerable `tar`) is not present in the runtime attack surface.
RUN rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
# Non-root runtime user.
RUN useradd --system --uid 10001 --create-home appuser
COPY --from=build --chown=appuser:appuser /app/.next/standalone ./
COPY --from=build --chown=appuser:appuser /app/.next/static ./.next/static
COPY --from=build --chown=appuser:appuser /app/public ./public
USER appuser
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 --start-period=15s \
    CMD node -e "fetch('http://127.0.0.1:3000/login').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
