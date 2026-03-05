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
WORKDIR /app
COPY --from=build /app/packages/ ./packages/
COPY --from=build /app/node_modules ./node_modules/
EXPOSE 3141
CMD ["node", "packages/executor/dist/entrypoint.js"]

# Agent stage
FROM node:22-alpine AS agent
WORKDIR /app
COPY --from=build /app/packages/ ./packages/
COPY --from=build /app/node_modules ./node_modules/
CMD ["node", "packages/agent/dist/loop.js"]
