# Sentinel — Secure Agent Runtime

Sentinel is a security-hardened agent runtime with process isolation between the agent (untrusted) and executor (trusted). Built as a local-first MVP, with Cloudflare Workers deployment planned for Phase 2.


## Quick Commands

| Command | Description |
|---------|-------------|
| `pnpm build` | tsup build all packages |
| `pnpm typecheck` | `tsc -b` (project references) |
| `pnpm test` | `vitest run` (unit tests) |
| `pnpm test:watch` | Vitest in watch mode |
| `pnpm test:coverage` | Vitest + V8 coverage |
| `pnpm lint` | `biome check .` |
| `pnpm lint:fix` | `biome check --write .` |
| `pnpm format` | `biome format --write .` |
| `pnpm format:check` | `biome format .` |
| `pnpm --filter @sentinel/<pkg> test` | Test a single package |
| `docker compose up` | Start executor + agent in Docker |
| `docker compose up executor` | Executor only |


## Getting Started

```bash
git clone <this-repo> && cd secure-openclaw
pnpm install
# API key stored in encrypted vault via `sentinel init`, not env vars
```


## Reference Documents

| Document | Purpose |
|----------|---------|
| `docs/server-hardening.md` | Infrastructure hardening reference with Sentinel architecture mapping |
| `docs/sentinel-hermes-addendum.md` | Hermes Agent feature additions [H1]-[H4] (ComputeBackend, bash classifier, session scoping, skill evaluation) |
| `.claude/agents/security-reviewer.md` | Subagent prompt for parallel security review |
| `.claude/skills/security-audit/SKILL.md` | `/security-audit` skill — validates 6 security invariants |
| `.claude/skills/upstream-sync/SKILL.md` | `/upstream-sync` skill — rebase on moltworker (user-only) |


## Architecture

### Phase 1: Local MVP — Two-Process Model

```
┌─────────────────────────┐         ┌──────────────────────────────┐
│     AGENT PROCESS        │  HTTP   │      EXECUTOR PROCESS         │
│     (untrusted, Docker)  │◄──────►│      (trusted, Docker)        │
│                          │ :3141  │                               │
│  - LLM API calls         │        │  - Credential Vault           │
│  - Reasoning / planning  │        │  - Tool execution             │
│  - Tool call generation  │        │  - Action classification      │
│  - Context management    │        │  - Confirmation routing       │
│                          │        │  - Audit logging (SQLite)     │
│  NO credentials          │        │  - MCP tool proxy             │
│  NO direct tool exec     │        │  Decrypts creds at exec time  │
└─────────────────────────┘         └──────────────────────────────┘
                                              │
                                    ┌─────────▼──────────┐
                                    │  CONFIRMATION TUI   │
                                    │  (host terminal)    │
                                    │  Shows ACTUAL params │
                                    └─────────────────────┘
```

Agent sends **Action Manifests** (typed JSON) to executor over HTTP :3141. Executor validates, classifies, optionally confirms with user, executes, audits, returns sanitized results. Confirmation TUI runs on host (trust anchor), never inside Docker.

### Phase 2: Cloudflare Workers Deployment (Future)

CF Worker + Sandbox containers replaces Docker. See `sentinel/` directory for CF Worker hooks (jiti-loaded `onBeforeToolCall` interceptors). D1 replaces SQLite for audit, KV for policy cache.

### OpenClaw Parallel Agent Model

OpenClaw supports parallel async instance spawning — relevant to executor concurrency design:
- **`parallel:` blocks** — OpenProse syntax spawns multiple sessions simultaneously, waits for all to complete
- **Concurrent `Task` calls** — multiple `Task({})` in one response = true parallelism
- **Sub-agent config** — `maxSpawnDepth: 2`, `maxChildrenPerAgent: 5`, `maxConcurrent: 8`, `runTimeoutSeconds: 900`
- **Sentinel implications**: executor must handle concurrent `/execute` requests without cross-session state leakage; audit logging (Invariant #2) must be session-scoped; each parallel instance is untrusted


## Project Layout

```
secure-openclaw/
├── packages/                    # MVP code (pnpm workspace)
│   ├── types/                   # Shared types + Zod schemas
│   ├── crypto/                  # Credential vault (AES-256-GCM)
│   ├── policy/                  # Deterministic action classifier
│   ├── audit/                   # Append-only SQLite audit log
│   ├── executor/                # Trusted process (Hono :3141)
│   ├── agent/                   # Untrusted process (LLM loop)
│   └── cli/                     # Host orchestrator + TUI
├── sentinel/                    # CF Worker hooks (Phase 2)
│   ├── hooks/                   # onBeforeToolCall extensions (jiti-loaded)
│   ├── manifests/               # Action manifest Zod schemas
│   ├── mem-hardening/           # claude-mem validation & caps
│   └── __tests__/               # Sentinel-specific tests
├── config/                      # Default classifications
├── data/                        # Runtime (gitignored): vault.enc, audit.db
├── docs/                        # Specs and reference docs
├── Dockerfile                   # Multi-stage: executor + agent images
├── docker-compose.yml           # Dev orchestration
├── biome.json                   # Lint + format config
├── tsconfig.base.json           # Shared strict TS config
├── vitest.workspace.ts          # Workspace-level test config
└── pnpm-workspace.yaml          # packages/*
```


## Security Invariants

These 6 rules are **non-negotiable**. Every PR must maintain them. Each has a required test.

| # | Invariant | Required Test |
|---|-----------|--------------|
| 1 | **No credentials in tool responses** — `credential-filter.ts` strips secrets before output reaches the agent | Assert: seeded API keys/tokens are removed |
| 2 | **All tool calls audited** — `onBeforeToolCall` writes immutable D1 record before execution | Assert: D1 audit rows match tool call count 1:1 |
| 3 | **Blocked tool categories enforced** — fs write, network egress, code exec denied unless allowlisted | Assert: blocked tool call rejected with correct error code |
| 4 | **Memory size caps enforced** — claude-mem entries capped at 10KB each, 100MB total | Assert: oversized observation truncated or rejected |
| 5 | **No credential storage in memory** — entries scanned for credential patterns before SQLite write | Assert: API key pattern in memory entry is rejected |
| 6 | **Policy changes require restart** — KV policy read at startup, no hot-reload | Assert: post-startup KV mutation has no effect |


## Conventions

### TypeScript
- **Strict mode** (`tsconfig.json` strict: true, target ES2022, module ESNext)
- **Zod** for all external input validation (tool args, API payloads, manifest schemas)
- **tsup** for package builds; coexists with wrangler for CF Worker bundling (Phase 2)
- **Never** include credential values in error messages, even truncated
- **Biome** for linting and formatting (not ESLint/Prettier/OXLint)

### Testing
- **Vitest** with V8 coverage; tests colocated as `*.test.ts` next to source
- **Security tests** are mandatory — each invariant above has a dedicated test
- **Pre-commit sequence:** `pnpm lint && pnpm typecheck && pnpm test`

### Upstream Fork Management
- **Never** modify upstream files without a `// SENTINEL:` comment explaining the change
- Track all upstream modifications in `UPSTREAM-DIFFS.md` (file, line, reason)
- New code goes in `sentinel/` — upstream `src/` modifications should be minimal
- To rebase on upstream: `git fetch upstream && git rebase upstream/main`
- Resolve conflicts by preserving `// SENTINEL:` blocks and re-applying diffs

### Action Manifests
All Sentinel actions use typed Zod schemas in `sentinel/manifests/`:

```typescript
import { z } from "zod";

export const FileReadManifest = z.object({
  action: z.literal("file.read"),
  path: z.string().min(1),
  encoding: z.enum(["utf-8", "base64"]).default("utf-8"),
  maxBytes: z.number().positive().max(10_000_000).optional(),
});
export type FileReadAction = z.infer<typeof FileReadManifest>;
```


## claude-mem Hardening

Sentinel wraps claude-mem (port 37777, SQLite + FTS5) with additional validation:

| Layer | What Sentinel Adds |
|-------|-------------------|
| **Input validation** | Standalone Zod schemas for all 4 MCP tool inputs (`search`, `timeline`, `get_observations`, `__IMPORTANT`) — upstream relies only on transitive MCP SDK validation |
| **Credential stripping** | Pre-write regex scan for API keys, tokens, passwords, connection strings; rejects matching entries |
| **Size caps** | Per-observation: 10KB max; total DB: 100MB max; enforced before SQLite write |
| **Blocked categories** | Observations tagged with blocked categories (e.g., `credential`, `secret`) are silently dropped |
| **`<private>` tag enforcement** | Validates that upstream `<private>` tag stripping is applied; logs if raw tags reach storage |


## Vector Search & Infrastructure Decisions

### Vector DB: sqlite-vec (MVP, Waves 1-3)
- **Choice**: [sqlite-vec](https://github.com/asg017/sqlite-vec) — SQLite extension adding `vec0` virtual tables
- **Why**: claude-mem already uses SQLite + FTS5; sqlite-vec adds semantic search to the same .db file (keyword + vector in one database)
- **Use cases**: Semantic memory retrieval, skill matching by embedding similarity, credential pattern anomaly detection
- **Integration**: Loads as extension into existing better-sqlite3 instance; no new infrastructure

### Vector DB: Zvec (Post-MVP, Wave 6+)
- **Choice**: [Zvec](https://github.com/alibaba/zvec) — C++ embedded vector DB with Node.js bindings
- **When**: After ComputeBackend ships; runs inside OpenSandbox containers on Hetzner
- **Why defer**: Native C++ dep is premature for local-first MVP; hybrid dense+sparse search valuable at scale

### Container Runtime: OpenSandbox (Post-MVP, Wave 6+)
- **Choice**: [OpenSandbox](https://github.com/alibaba/OpenSandbox) — self-hosted sandbox platform (Docker/K8s)
- **Replaces**: CF Containers as `DockerBackend` target
- **Why**: gVisor/Kata/Firecracker isolation > CF process-level; per-sandbox egress policies; built-in Playwright
- **When**: After `ComputeBackend` interface is stable (Wave 3), evaluated for Wave 6 integration

### Open Design Work (sqlite-vec)
- **Status**: Paused — resume before Wave 3 implementation
- **Remaining decisions**: Embedding model choice (local vs API), `vec0` table schema, hybrid FTS5+vec0 query strategy, embedding generation pipeline at observation write time

### Evaluated & Rejected
- **LEANN** — Python-only, LlamaIndex dependency; wrong ecosystem for TypeScript project
- **Cloudflare Vectorize** — Network latency for local agent loop; can't send credential-adjacent content to cloud for embedding
- **Zvec in MVP** — C++ native dep adds build complexity for v0.2.0 software; sqlite-vec covers MVP needs

### Evaluation Queue
- **CopilotKit** — Generative UI framework for AI-native apps; evaluate for agent frontend layer
  - Org: https://github.com/CopilotKit
  - Key repos: `generative-ui`, `deep-agents-demo`, `with-mcp-apps`
- **ag-ui** — Agent-UI protocol for streaming agent state to frontends; evaluate for MCP app integration
  - Repo: https://github.com/ag-ui-protocol/ag-ui


## Environment Variables

| Variable | Scope | Description |
|----------|-------|-------------|
| `ANTHROPIC_API_KEY` | Container | AI provider key (required) |
| `MOLTBOT_GATEWAY_TOKEN` | Worker | Gateway access protection |
| `CF_ACCESS_TEAM_DOMAIN` | Worker | Cloudflare Access auth domain |
| `CF_ACCESS_AUD` | Worker | Cloudflare Access audience tag |
| `R2_ACCESS_KEY_ID` | Worker | R2 persistence credentials |
| `R2_SECRET_ACCESS_KEY` | Worker | R2 persistence credentials |
| `CF_ACCOUNT_ID` | Worker | Cloudflare account ID |
| `SENTINEL_POLICY_VERSION` | Container | Policy version string (read at startup) |
| `SENTINEL_AUDIT_ENABLED` | Container | Enable/disable D1 audit logging |
| `CLAUDE_MEM_DATA_DIR` | Container | claude-mem SQLite path override |

Secrets are stored via `wrangler secret put`. Local dev uses `.dev.vars` (see `.dev.vars.example`). **Never** commit `.dev.vars` with real values.


## Automations

### Hooks (`.claude/settings.json`)
- **PreToolUse**: Blocks edits to `.dev.vars` / `.env` files (use `wrangler secret put` instead)
- **PostToolUse**: Auto-formats `.ts/.tsx` with Biome on every edit

### Skills
- `/security-audit` — Validates all 6 security invariants (run before every commit)
- `/upstream-sync` — Rebase on moltworker, preserve `// SENTINEL:` markers (user-only)

### Subagents (`.claude/agents/`)
- `security-reviewer` — Parallel security review against invariants + OWASP patterns

### MCP Servers (`.claude/.mcp.json`)
- `cloudflare-bindings` — Query D1/KV/R2 directly (OAuth on first use)
- `cloudflare-observability` — Tail Worker logs during dev

### Allowed Commands
Defined in `.claude/settings.json` — includes wrangler, test, lint, and typecheck commands.


## Gotchas

- **Biome v2, not v1** — config schema changed significantly; use `biome.json` with `$schema` v2.4.6+
- **pnpm workspaces** — use `pnpm --filter @sentinel/<pkg>` to run commands in specific packages
- **better-sqlite3** — native module; needs node-gyp build tools (Python, make, C++ compiler)
- **No D1/KV in MVP** — D1 and KV are Phase 2 (CF Workers); MVP uses local SQLite + encrypted files
- **Sandbox blocks `.claude/` writes** — creating skills/agents may require disabling sandbox temporarily
- **`docs/server-hardening.md`** — infrastructure hardening reference with Sentinel architecture mapping
- **Container registry (ghcr.io)** — Not needed for local MVP; `docker compose build` suffices. Set up ghcr.io when hitting Phase 2 / DockerBackend VPS deployment: GitHub Action that builds and pushes to ghcr.io on tagged releases. That's the natural inflection point where it pays off.
- **Biome v2 monorepo globs** — `!dist` only excludes top-level; use `!**/dist` for `packages/*/dist/`
- **tsup `--dts` in Docker** — Fails with composite project references (TS6307); Dockerfile uses `tsc -b` instead
- **Docker entrypoint** — `packages/executor/src/entrypoint.ts` is the container startup file; `server.ts` only exports `createApp`
- **`noImplicitAnyLet`** — Biome catches `let x;` even when TS allows it; always annotate: `let x: Type;`
- **Executor concurrency** — OpenClaw can spawn parallel agent instances; executor `:3141` must handle concurrent `/execute` POST requests with session-scoped isolation (no shared mutable state between requests)


## Build Progress

> Updated 2026-03-05: Phase 1 complete (163 tests, 7 packages). Docker validated (executor container starts, healthcheck passes). Phase 2 = CF Workers.

### Phase 1: Local MVP

#### Step 0 — Scaffolding
- [x] Git init + initial commit with existing docs
- [x] Update CLAUDE.md (pnpm, Biome, tsup, Docker arch)
- [x] Create monorepo scaffolding (pnpm workspace, tsconfig, biome, vitest)
- [x] Verify toolchain (pnpm install, biome check, tsc, vitest)

#### Step 1 — `packages/types` ✅
- [x] ActionManifest, ActionCategory, ToolResult, ToolName (string + constants)
- [x] PolicyDecision, SentinelConfig, ToolClassification, ClassificationOverride
- [x] AuditEntry, AgentCard, A2ATask, A2AArtifact (stubs)
- [x] McpServerConfig, ToolRegistryEntry (MCP compatibility)

#### Step 2 — `packages/crypto` ✅
- [x] CredentialVault class (AES-256-GCM, PBKDF2 SHA-512 600k iterations)
- [x] Tests: round-trip, wrong password, destroy zeros key, no plaintext in file (8 tests)

#### Step 3 — `packages/policy` ✅
- [x] classify(manifest, config) → PolicyDecision
- [x] Bash parser: read/write/dangerous classification
- [x] MCP tool classification (unknown = write, per-server overrides)
- [x] Tests: 94 tests covering classification rules

#### Step 4 — `packages/audit` ✅
- [x] AuditLogger class (SQLite, append-only)
- [x] Credential redaction in parameters_summary
- [x] Tests: round-trip, redaction, session filtering (27 tests)

#### Step 5 — `packages/executor` ✅
- [x] Hono server :3141 (POST /execute, GET /health, GET /agent-card, GET /tools, POST /confirm/:id)
- [x] Tool registry (built-in: bash, read_file, write_file, edit_file)
- [x] Confirmation flow (auto-approve reads, confirm writes/dangerous)
- [x] Deny-list path filtering (defense in depth) — 12 tests

#### Step 6 — `packages/agent` ✅
- [x] Agent loop: reason → manifest → POST executor → observe → repeat
- [x] Anthropic SDK with streaming
- [x] Tool definitions from executor's GET /tools — 21 tests

#### Step 7 — `packages/cli` ✅
- [x] sentinel chat, vault, audit, config, init
- [x] In-process executor (local dev, Docker deferred)
- [x] Confirmation TUI (@clack/prompts + chalk) — 1 test

### Phase 2: CF Workers Deployment (Future)

Original Waves 1-6 from Hermes Addendum. Requires CF account + moltworker fork. See `sentinel/` directory structure and `docs/sentinel-hermes-addendum.md` for full spec.

#### Research & Claude Chat Migration
- [ ] **Copy Claude Desktop Sentinel chats** using Chrome extension — design decisions, threat models
- [ ] **Read Reddit security warning** — https://www.reddit.com/r/ClaudeAI/comments/1qn53gl/warning_i_tried_clawdbot_powered_by_claude/
- [ ] **Read "Google suspends OpenClaw over token misuse"** — validates credential filtering design
- [ ] **Review ClawMetry** (Product Hunt) — observability tool, potential audit dashboard integration

#### Intelligent Model Routing with Plano (Post-MVP)
- [ ] **Integrate [Plano](https://github.com/katanemo/plano) as AI-native proxy** — 4B-param router for model selection (Kimi K2.5 vs Claude Opus 4.6)
- [ ] **Configure routing rules** — prompt classification criteria by task type
- [ ] **Wire Plano into Sentinel** — routed requests still pass through policy engine + audit
