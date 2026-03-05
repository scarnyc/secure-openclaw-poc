# Build stage
FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/ ./packages/
RUN pnpm install --frozen-lockfile
RUN pnpm build

# Executor stage
FROM node:22-alpine AS executor
RUN corepack enable
WORKDIR /app
COPY --from=build /app/packages/executor/dist ./executor/
COPY --from=build /app/packages/types/dist ./types/
COPY --from=build /app/packages/crypto/dist ./crypto/
COPY --from=build /app/packages/policy/dist ./policy/
COPY --from=build /app/packages/audit/dist ./audit/
COPY --from=build /app/node_modules ./node_modules/
EXPOSE 3141
CMD ["node", "executor/server.js"]

# Agent stage
FROM node:22-alpine AS agent
RUN corepack enable
WORKDIR /app
COPY --from=build /app/packages/agent/dist ./agent/
COPY --from=build /app/packages/types/dist ./types/
COPY --from=build /app/node_modules ./node_modules/
CMD ["node", "agent/loop.js"]
