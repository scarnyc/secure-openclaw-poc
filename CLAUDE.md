# Sentinel — Secure Agent Runtime

Sentinel is a security-hardened agent runtime with process isolation between the agent (untrusted) and executor (trusted). Local-first, runs on Mac Mini via Docker Compose.

## Current Phase: Phase 1 — Harden for Confidence

**Plan**: `docs/plans/path-a-v2-adopt-openfang-primitives.md`

**Phase 0 completed** (PR #7, 335 tests): bug fixes, confirmation TUI, path whitelist, OWASP gate.


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


## Local Development

### Prerequisites
- Node.js 18+
- pnpm 9+

### Setup
```bash
pnpm install
pnpm typecheck   # Verify TypeScript
pnpm test         # Run all tests (335+)
```

### Running locally
```bash
sentinel init     # First-time: set master password, store API keys
sentinel chat     # Start interactive agent session with TUI confirmation
```

### Environment
- `SENTINEL_ALLOWED_ROOTS` — comma-separated path whitelist (defaults to cwd)
- `SENTINEL_DOCKER=true` — enables container-mode restrictions
- `SENTINEL_MODERATION_MODE=enforce|warn|off` — content moderation
- See `.dev.vars.example` for all variables


## Reference Documents

| Document | Purpose |
|----------|---------|
| `docs/server-hardening.md` | Infrastructure hardening reference with Sentinel architecture mapping |
| `docs/owasp-reviews/phase-0.md` | Phase 0 OWASP gate review (7 findings, all MEDIUM/LOW) |
| `.claude/agents/security-reviewer.md` | Subagent prompt for parallel security review |
| `.claude/skills/security-audit/SKILL.md` | `/security-audit` skill — validates 6 security invariants |
| `.claude/skills/upstream-sync/SKILL.md` | `/upstream-sync` skill — rebase on moltworker (user-only) |


## Architecture

### Two-Process Model

```
┌─────────────────────────┐         ┌──────────────────────────────┐
│     AGENT PROCESS        │  HTTP   │      EXECUTOR PROCESS         │
│     (untrusted, Docker)  │◄──────►│      (trusted, Docker)        │
│     internal network     │ :3141  │                               │
│     NO internet access   │        │  - Credential Vault           │
│                          │        │  - Tool execution             │
│  - Reasoning / planning  │        │  - Action classification      │
│  - Tool call generation  │        │  - Confirmation routing       │
│  - Context management    │        │  - Audit logging (SQLite)     │
│                          │        │  - LLM proxy (/proxy/llm/*)  │
│  NO credentials          │        │  - Content moderation         │
│  NO direct tool exec     │        │  - MCP tool proxy             │
│  NO direct internet      │        │  Decrypts creds at exec time  │
└─────────────────────────┘         └──────────────────────────────┘
         │ LLM calls via                      │         │
         │ /proxy/llm/*                       │    ┌────▼─────────────┐
         └────────────────────────────────────┘    │ LLM APIs         │
                                    │              │ (anthropic,       │
                                    │              │  openai, gemini)  │
                                    │              └──────────────────┘
                                    │
                          ┌─────────▼──────────┐
                          │  CONFIRMATION TUI   │
                          │  (host terminal)    │
                          │  Shows ACTUAL params │
                          └─────────────────────┘
```

Agent sends **Action Manifests** (typed JSON) to executor over HTTP :3141. Executor validates, classifies, moderates, optionally confirms with user, executes, audits, returns sanitized results. Agent container has `internal: true` network — no direct internet access. LLM calls are proxied through executor's `/proxy/llm/*` endpoint, which injects API keys and restricts to allowlisted hosts. Confirmation TUI runs on host (trust anchor), never inside Docker.

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
├── sentinel/                    # Sentinel-specific extensions
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
| 1 | **No credentials in tool responses** — unified `credential-patterns.ts` strips secrets (Anthropic, OpenAI, Gemini, GitHub, Slack, AWS, DB strings) before output reaches agent | Assert: seeded API keys/tokens are removed |
| 2 | **All tool calls audited** — audit logger writes SQLite record with `agentId` before execution | Assert: audit rows match tool call count 1:1, include agentId |
| 3 | **Blocked tool categories enforced** — fs write, network egress, code exec denied unless allowlisted | Assert: blocked tool call rejected with correct error code |
| 4 | **Memory size caps enforced** — claude-mem entries capped at 10KB each, 100MB total | Assert: oversized observation truncated or rejected |
| 5 | **No credential storage in memory** — entries scanned for credential patterns before SQLite write | Assert: API key pattern in memory entry is rejected |
| 6 | **Policy changes require restart** — config frozen via `Object.freeze(structuredClone())` at startup | Assert: frozen config mutation throws TypeError |


## Conventions

### TypeScript
- **Strict mode** (`tsconfig.json` strict: true, target ES2022, module ESNext)
- **Zod** for all external input validation (tool args, API payloads, manifest schemas)
- **tsup** for package builds
- **Never** include credential values in error messages, even truncated
- **Biome** for linting and formatting (not ESLint/Prettier/OXLint)

### Credential Patterns
- **Single source of truth** in `packages/types/src/credential-patterns.ts`
- Both `executor/credential-filter.ts` and `audit/redact.ts` import from types
- Add new patterns here only — never maintain separate pattern lists

### Bash Sandboxing
- **Interpreter inline-exec** (`python3 -c`, `node -e`, etc.) classified as "dangerous" — always requires confirmation
- **firejail** wrapping when `SENTINEL_BASH_SANDBOX=firejail` — `--net=none --private` for defense-in-depth
- firejail is Linux-only; local Mac dev falls back to unsandboxed execution

### Content Moderation
- **Mode**: `SENTINEL_MODERATION_MODE=enforce|warn|off` (default: off in local dev)
- Scanner in `packages/executor/src/moderation/scanner.ts`
- Pre-execute: scans request parameters; post-execute: scans tool output
- `enforce`: blocked content returns generic error; `warn`: logged but not blocked

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


## Future Work

Details in `docs/plans/path-a-v2-adopt-openfang-primitives.md` and MEMORY.md evaluation queue.

- Phase 1: Merkle audit, SSRF, loop guard, rate limiter, PII scrubber
- Phase 2: Google Workspace, OpenClaw agents, sqlite-vec, CopilotKit/ag-ui
- Phase 2 security: email injection, data compartmentalization, memory isolation, PII (NER)


## Environment Variables

| Variable | Scope | Description |
|----------|-------|-------------|
| `ANTHROPIC_API_KEY` | Container | Claude AI provider key (required) |
| `OPENAI_API_KEY` | Container | GPT AI provider key (required) |
| `GEMINI_API_KEY` | Container | Google AI provider key (required) |
| `SENTINEL_POLICY_VERSION` | Container | Policy version string (read at startup) |
| `SENTINEL_AUDIT_ENABLED` | Container | Enable/disable audit logging |
| `CLAUDE_MEM_DATA_DIR` | Container | claude-mem SQLite path override |

API keys stored in encrypted vault via `sentinel init`. Local dev uses `.dev.vars` (see `.dev.vars.example`). **Never** commit `.dev.vars` with real values.


## Automations

### Hooks (`.claude/settings.json`)
- **PreToolUse**: Blocks edits to `.dev.vars` / `.env` files (use envchain or the encrypted vault instead)
- **PostToolUse**: Auto-formats `.ts/.tsx` with Biome on every edit

### Skills
- `/security-audit` — Validates all 6 security invariants (run before every commit)
- `/upstream-sync` — Rebase on moltworker, preserve `// SENTINEL:` markers (user-only)

### Subagents (`.claude/agents/`)
- `security-reviewer` — Parallel security review against invariants + OWASP patterns
- `adversarial-tester` — Runs adversarial tests, red teaming, pen tests and mutation testing to ensure security and privacy by design

### Allowed Commands
Defined in `.claude/settings.json` — includes test, lint, and typecheck commands.


## Gotchas

- **Biome v2, not v1** — config schema changed significantly; use `biome.json` with `$schema` v2.4.6+
- **pnpm workspaces** — use `pnpm --filter @sentinel/<pkg>` to run commands in specific packages
- **better-sqlite3** — native module; needs node-gyp build tools (Python, make, C++ compiler)
- **Sandbox blocks `.claude/` writes** — creating skills/agents may require disabling sandbox temporarily
- **Biome v2 monorepo globs** — `!dist` only excludes top-level; use `!**/dist` for `packages/*/dist/`
- **tsup `--dts` in Docker** — Fails with composite project references (TS6307); Dockerfile uses `tsc -b` instead
- **Docker entrypoint** — `packages/executor/src/entrypoint.ts` is the container startup file; `server.ts` only exports `createApp`
- **`noImplicitAnyLet`** — Biome catches `let x;` even when TS allows it; always annotate: `let x: Type;`
- **Executor concurrency** — OpenClaw can spawn parallel agent instances; executor `:3141` must handle concurrent `/execute` POST requests with session-scoped isolation (no shared mutable state between requests)
- **Docker `internal: true`** — agent container cannot reach internet; all LLM calls go through executor's `/proxy/llm/*` endpoint
- **`ANTHROPIC_BASE_URL`** — must be set in agent container to `http://executor:3141/proxy/llm` to route through proxy
- **firejail is Linux-only** — local Mac dev falls back to unsandboxed bash execution; firejail wrapping only active when `SENTINEL_BASH_SANDBOX=firejail`
- **`SENTINEL_DOCKER=true`** — enables write-file path restriction to `/app/data/`; set in executor container env
- **O_NOFOLLOW + realpath** — `open()` with `O_NOFOLLOW` must target the user-supplied path, not the realpath-resolved path (realpath already resolves symlinks, defeating the check); returns `ELOOP` on macOS, `EMLINK` on some Linux
- **Archived plans** — `docs/plans/archived/` contains superseded Phase 1.5 design docs (TypeScript policy engine approach)


## Build Progress

### Phase 1: Local MVP ✅ (Merged)

Completed 2026-03-05. 163 tests, 7 packages, Docker validated. Merged to `main` (commit `0af8fcc`).

**Packages delivered:** types, crypto (AES-256-GCM vault), policy (94 classification tests), audit (SQLite, credential redaction), executor (Hono :3141, deny-list filtering), agent (Anthropic SDK streaming), cli (TUI + in-process executor).

### Phase 1.5: Container Hardening ✅ (Merged)

231 tests, 16 test files. Network egress lockdown, bash hardening, config freeze, unified credential filter, agentId in manifests, workspace mounts, content moderation, Docker hardening.

### Phase 0: Make It Usable ✅ (Merged)

335 tests (93 new). PR #7, merged 2026-03-08. Bug fixes, confirmation TUI, path whitelist, secret zeroization, OWASP gate review.

### Hardening (Phase 1)

See Phase 1 roadmap in plan doc. Threat model: protect local Mac Mini (API keys, files, Google Workspace).

### Backlog

#### Infrastructure & Integration
- [ ] sqlite-vec integration design — embedding model, vec0 schema, hybrid FTS5+vec0 queries
- [ ] Claude-mem setup (modify for security)
- [ ] Plano model routing — GPT latest + fallbacks to Claude Opus, Gemini Flash Lite 3.1; reference [Claude chat 1](https://claude.ai/share/d7e9dbba-dec4-4f28-a3b7-b9920b76bd10), [Claude chat 2](https://claude.ai/share/c67fb5e7-eb4b-4356-be0e-d7ce66dd359c), [OpenAI model docs](https://developers.openai.com/api/docs/guides/latest-model)
- [ ] CopilotKit integration — dedicated chatbot use case + AI learning prototype; ag-ui evaluation for MCP app integration; A2A for multi-agent orchestration
- [ ] Write-action HITL via ag-ui — replace TUI confirmation with rich ag-ui frontend
- [ ] UCP integration — unified context protocol via ag-ui + CopilotKit
- [ ] Google Model Armor — add to executor content moderation pipeline
- [x] OWASP Top 10 review — Phase 0 gate complete (`docs/owasp-reviews/phase-0.md`)
- [ ] Research: Reddit security warning, ClawMetry review
- [ ] Claude Code integrations and heartbeats for coding tasks via notes

See `docs/plans/path-a-v2-adopt-openfang-primitives.md` §Phase 2 for security gaps and agent roster.
