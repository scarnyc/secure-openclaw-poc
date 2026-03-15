# Build stage
FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json tsconfig.json ./
COPY packages/ ./packages/
RUN pnpm install --frozen-lockfile
# Clean stale dist/ from COPY (tsup bundles break native ESM imports)
# Remove test files before build — they import devDependencies not available in Docker
RUN find packages -name dist -type d -exec rm -rf {} + 2>/dev/null; true
RUN find packages -name '*.tsbuildinfo' -delete 2>/dev/null; true
RUN find packages -name '*.test.ts' -delete 2>/dev/null; true
RUN npx tsc -b

# Executor stage
FROM node:22-alpine AS executor
# SENTINEL: H2 — container hardening (read_only, cap_drop ALL, no-new-privileges)
# provides defense-in-depth; firejail omitted (not in Alpine repos)
RUN apk add --no-cache dumb-init
WORKDIR /app
COPY --from=build /app/packages/ ./packages/
COPY --from=build /app/node_modules ./node_modules/
# SENTINEL: M9 — Remove dev dependencies and test files from production image
RUN find /app/packages -name "*.test.ts" -delete && \
    find /app/packages -name "*.test.js" -delete && \
    find /app/packages -name "__tests__" -type d -exec rm -rf {} + 2>/dev/null; true
RUN mkdir -p /app/data && chown node:node /app/data
USER node
EXPOSE 3141
ENTRYPOINT ["dumb-init", "--"]
# SENTINEL: --secure-heap mlock()s OpenSSL key material, preventing swap to disk
CMD ["node", "--secure-heap=65536", "--secure-heap-min=64", "packages/executor/dist/entrypoint.js"]

# Agent stage
FROM node:22-alpine AS agent
RUN apk add --no-cache dumb-init
WORKDIR /app
COPY --from=build /app/packages/ ./packages/
COPY --from=build /app/node_modules ./node_modules/
USER node
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "packages/agent/dist/loop.js"]

# OpenClaw Gateway stage
# SENTINEL: OpenClaw is not yet published to npm. This stage runs a lightweight
# plugin host that loads the Sentinel plugin, exposes /health, and will be
# replaced with `openclaw gateway` once the package is available.
FROM node:22-alpine AS openclaw-gateway
RUN apk add --no-cache dumb-init
WORKDIR /app
# Copy Sentinel plugin from build stage
COPY --from=build /app/packages/openclaw-plugin/dist/ ./plugin/dist/
COPY --from=build /app/packages/openclaw-plugin/openclaw.plugin.json ./plugin/
COPY --from=build /app/packages/openclaw-plugin/package.json ./plugin/
# Copy types dist (plugin dependency)
COPY --from=build /app/packages/types/dist/ ./packages/types/dist/
COPY --from=build /app/packages/types/package.json ./packages/types/
# Node modules for plugin runtime dependencies
COPY --from=build /app/node_modules ./node_modules/
RUN mkdir -p /app/data && chown node:node /app/data
USER node
EXPOSE 8080
ENTRYPOINT ["dumb-init", "--"]
# Lightweight plugin host: health endpoint + plugin readiness check
CMD ["node", "-e", "\
const http = require('http');\
const fs = require('fs');\
const pluginExists = fs.existsSync('/app/plugin/dist/register.js');\
const manifest = pluginExists ? JSON.parse(fs.readFileSync('/app/plugin/openclaw.plugin.json','utf8')) : null;\
console.log(`[openclaw-gateway] Plugin: ${manifest?.name ?? 'not found'} v${manifest?.version ?? '?'}`);\
console.log(`[openclaw-gateway] Executor: ${process.env.SENTINEL_EXECUTOR_URL ?? 'not configured'}`);\
const server = http.createServer((req,res) => {\
  if (req.url === '/health') {\
    res.writeHead(200, {'Content-Type':'application/json'});\
    res.end(JSON.stringify({status:'ok',plugin:manifest?.name,version:manifest?.version}));\
  } else {\
    res.writeHead(404); res.end();\
  }\
});\
server.listen(8080, '0.0.0.0', () => console.log('[openclaw-gateway] Listening on :8080'));\
"]
