# Build stage
FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json tsconfig.json ./
COPY packages/ ./packages/
RUN pnpm install --frozen-lockfile
RUN npx tsc -b

# Executor stage
FROM node:22-alpine AS executor
RUN apk add --no-cache dumb-init
WORKDIR /app
COPY --from=build /app/packages/ ./packages/
COPY --from=build /app/node_modules ./node_modules/
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
