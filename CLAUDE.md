# Sentinel — Secure Agent Runtime

Sentinel is a security-hardened agent runtime with process isolation between the agent (untrusted) and executor (trusted). Local-first, runs on Mac Mini via Docker Compose.

## Current Phase: Phase 2 — Integrations + Real Agents

**Next Steps**:
1. Context budget enforcement: per-result 30% cap, global 75% cap
2. Tool recursion depth limiting: max depth 5 for agent-to-agent calls
3. OpenClaw post-install: configure Brave Search provider (`openclaw configure --section model`), configure embedding provider for memory search, run `openclaw security audit --deep`
**Roadmap**: `docs/plans/path-a-v2-adopt-openfang-primitives.md`
**Wave spec**: `docs/superpowers/specs/2026-03-10-phase-2-waves-design.md`
4. Set Anthropic and Gemini API keys to work with Plano
Optional follow-up (separate commit) | The config only has sentinel-openai provider routing through the proxy. There's no sentinel-anthropic or sentinel-gemini provider. The Anthropic auth profile uses direct `mode: "token"` — which means Anthropic API calls would bypass Sentinel's proxy. This may be intentional if you're only using GPT-5.4 for now, but worth noting for later. Investigate Anthropic API failures — The 34% failure rate and malformed /anthropic/v1/messages path suggest a ANTHROPIC_BASE_URL misconfiguration. Fix the URL double-prefix issue.
5. Update TIER_CONSTRAINTS strings in setup-openclaw.ts to match the new conversational tone (currently they read like policy docs too)
6. Update the inline fallback template at setup-openclaw.ts:165-171 (only fires if template file missing)
7. Set up sentinel memory plugin. Add memory operation test scenarios — Invariants 4 (size caps) and 5 (no credentials in memory) are completely unexercised in production. Generate test workloads that exercise memory writes. OpenClaw memory isolation — separate memory systems (Phase 3)
8. Fix set-up and create guide to make it more intuitive and user friendly
9. Right now openclaw classifies everything as a write command. Add a name-based heuristic (or probabalistic) in the classifier — tools with search, read, list, get, view in the name default to "read" instead of "write"
10. Route ALL OpenClaw execution through Sentinel (blocked by OpenClaw hook API — `before_tool_call` can't replace execution; Docker network isolation mitigates):
- Execution result passthrough | plugin returns Sentinel's filtered output as OpenClaw tool result (depends on full execution routing)
- Context compaction — per-result 30% cap, global 75% cap (performance optimization, not security)
11. Update SOUL.md and AGENTS.md so that openclaw knows what sentinel is aware of it. Keep the level of detail 'as needed' so it can't modify sentinel settings
12. Webhook support in Docker — requires inbound connections incompatible with `internal: true` (cloud deployment scope)
13. Plugin hot-reload — currently requires gateway restart
14. secure telegram channels upon server wind-down
15. Fix vault password masking upon `sentinel start`
16. Custom undici dispatcher | Full content visibility through CONNECT tunnels (follow-up to domain-level CONNECT proxy). Placeholder injection at proxy. More work but no compromises. Could be built as a general-purpose solution for any library using undici
17. Populate parameters_summary in /classify — Change classify-endpoint.ts:107 from parameters_summary: "" to parameters_summary: redactCredentials(JSON.stringify(params).substring(0, 500)) for audit forensics. 
18. Stress-test rate limiter and loop guard — These guards have never fired in production. Consider adding a load test that generates >60 req/min to verify they work under pressure, not just in unit tests.


**Phase 1 completed** (PR #8, 490 tests). **Memory store** (PR #9, 542 tests). **Phase 2** decomposes into 4 waves.

**Wave Progress**
- [x] Wave 2.1: Security Primitives — Ed25519 signing + irreversible classification (553 tests)
- [x] Wave 2.2: Google Workspace CLI + Email Defense (583 tests)
- [x] Wave 2.2b: Credential Zeroization — useCredential helper, V8 string lifetime minimization (652 tests)
- [x] Wave 2.2c: Pen Test Fixes — 16 findings across 4 waves (845 tests)
- [x] Wave 2.3a: OpenClaw + Sentinel Plugin — types, /classify, /filter-output, plugin package, delegate.code, setup CLI (48 tests)
- [x] Wave 2.3b: OpenClaw + Sentinel E2E Integration — 8 integration tests (903 tests)
- [x] Wave 2.3c: GWS Security Guardrails — Docker defaults, gwsDefaultDeny, fail-closed plugin, test refactoring (1106 tests)
- [ ] Wave 2.4: LLM Infrastructure (Plano routing, prompt caching, Promptfoo)

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
| `sentinel start` | Build, start Docker, wait for healthy (executor + gateway) |
| `sentinel start executor agent` | Start specific services |
| `sentinel stop` | Stop all Docker services |
| `docker compose up` | Start executor + agent in Docker (manual) |


## Getting Started

```bash
git clone <this-repo> && cd secure-openclaw
pnpm install
pnpm build        # tsc --build + tsup for all packages
pnpm typecheck    # Verify TypeScript
sentinel init     # First-time: set master password, store API key (interactive TUI)
sentinel start    # Build Docker, start executor, wait for healthy
```

**`sentinel` CLI** — run via `node packages/cli/dist/main.js <command>` or `pnpm --filter @sentinel/cli exec sentinel <command>`.

### Prerequisites
- Node.js 18+
- pnpm 9+
- Docker Desktop (required for production deployment)
- Rust toolchain (`rustup` or `brew install rust`) — for `crypto-native` package

### Running
```bash
sentinel start              # Build + start executor in Docker, wait for healthy
sentinel start executor agent  # Start specific services
sentinel stop               # Tear down all Docker services
sentinel chat               # Start interactive agent session with TUI confirmation
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
| `.claude/skills/security-audit/SKILL.md` | `/security-audit` skill — validates 12 security invariants |
| `.claude/skills/upstream-sync/SKILL.md` | `/upstream-sync` skill — rebase on moltworker (user-only) |
| `.rampart/policy.yaml` | Host-level Rampart firewall policy (tfstate, data protection, security code gate) |
| `docs/guides/openclaw-sentinel-setup.md` | OpenClaw + Sentinel deployment guide |


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
│  NO credentials          │        │  - Egress proxy (/proxy/egress) │
│  NO direct tool exec     │        │  - Content moderation         │
│  NO direct internet      │        │  - MCP tool proxy             │
│                          │        │  Decrypts creds at exec time  │
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

Agent sends **Action Manifests** (typed JSON) to executor over HTTP :3141. Executor validates, classifies, moderates, optionally confirms with user, executes, audits, returns sanitized results. OpenClaw agents use `/classify` (classification-only) and `/filter-output` (credential/PII scrubbing) endpoints via the `@sentinel/openclaw-plugin` package. Agent container has `internal: true` network — no direct internet access. LLM calls are proxied through executor's `/proxy/llm/*` endpoint, which injects API keys and restricts to allowlisted hosts. External API calls (Telegram, etc.) are proxied through executor's `/proxy/egress` endpoint, which injects domain-scoped credentials from the vault and applies SSRF protection.

### Web Confirmation Flow
Telegram/Slack sends web link with HMAC token → user opens on phone → `GET /confirm-ui/:id?token=...&expires=...` renders HTML → user clicks Approve → `POST /confirm/:id?token=...&expires=...` → resolves pending `/confirm-only` long-poll → OpenClaw proceeds. SSE at `/confirmations/stream` emits ag-ui Custom events (confirmation_requested/confirmation_resolved). Cloudflare tunnel (`cloudflared`) provides public HTTPS URL — auto-started by `sentinel start`.

### OpenClaw Parallel Agent Model

OpenClaw supports parallel async instance spawning — relevant to executor concurrency design:
- **`parallel:` blocks** — OpenProse syntax spawns multiple sessions simultaneously, waits for all to complete
- **Concurrent `Task` calls** — multiple `Task({})` in one response = true parallelism
- **Sub-agent config** — `maxSpawnDepth: 2`, `maxChildrenPerAgent: 5`, `maxConcurrent: 8`, `runTimeoutSeconds: 900`
- **Sentinel implications**: executor must handle concurrent `/execute` requests without cross-session state leakage; audit logging (Invariant #2) must be session-scoped; each parallel instance is untrusted


## Project Layout

```
secure-openclaw/
├── .rampart/                    # Rampart project policy (host-level firewall)
├── packages/                    # MVP code (pnpm workspace)
│   ├── types/                   # Shared types + Zod schemas
│   ├── crypto/                  # Credential vault (AES-256-GCM) + Ed25519 signing
│   ├── policy/                  # Deterministic action classifier
│   ├── audit/                   # Append-only SQLite audit log
│   ├── executor/                # Trusted process (Hono :3141)
│   ├── agent/                   # Untrusted process (LLM loop)
│   ├── cli/                     # Host orchestrator + TUI
│   ├── memory/                  # Hybrid retrieval memory store (SQLite + FTS5 + sqlite-vec)
│   ├── guard-client/            # Framework-agnostic Guard SDK (classify, filter, confirm, LLM proxy)
│   └── openclaw-plugin/         # OpenClaw → Sentinel bridge (classify, filter, delegate)
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

These 12 rules are **non-negotiable**. Every PR must maintain them. Each has a required test.

| # | Invariant | Required Test |
|---|-----------|--------------|
| 1 | **No credentials in tool responses** — unified `credential-patterns.ts` strips secrets (Anthropic, OpenAI, Gemini, GitHub, Slack, AWS, DB strings) before output reaches agent | Assert: seeded API keys/tokens are removed |
| 2 | **All tool calls audited** — audit logger writes SQLite record with `agentId` before execution | Assert: audit rows match tool call count 1:1, include agentId |
| 3 | **Blocked tool categories enforced** — fs write, network egress, code exec denied unless allowlisted | Assert: blocked tool call rejected with correct error code |
| 4 | **Memory size caps enforced** — claude-mem entries capped at 10KB each, 100MB total | Assert: oversized observation truncated or rejected |
| 5 | **No credential storage in memory** — entries scanned for credential patterns before SQLite write | Assert: API key pattern in memory entry is rejected |
| 6 | **Policy changes require restart** — config frozen via `Object.freeze(structuredClone())` at startup | Assert: frozen config mutation throws TypeError |
| 7 | **Merkle chain tamper-evident + Ed25519 signed** — SHA-256 hash chain over audit rows; optional Ed25519 manifest signatures; `verifyChain(publicKey?)` detects tampering and signature forgery | Assert: modified audit row detected by `verifyChain()`; tampered signature detected |
| 8 | **SSRF blocked** — private IPs, localhost, 169.254.x, IPv6 ULA/link-local rejected before outbound requests | Assert: private IPs / localhost / 169.254.x rejected |
| 9 | **Per-agent rate limiting** — GCRA algorithm enforces per-agent request rate with configurable burst | Assert: burst exceeding rate gets 429-equivalent rejection |
| 10 | **PII scrubbed from outbound** — SSN, phone, email, salary patterns redacted before output reaches agent | Assert: SSN in tool output → `[PII_REDACTED]` |
| 11 | **Loop guard blocks storms** — identical tool calls tracked per-agent; warn at 3, block at 5 in 60s window | Assert: >N identical calls in M seconds → blocked |
| 12 | **Per-agent path whitelist** — realpath-resolved file access restricted to `allowedRoots` with symlink escape prevention | Assert: agent with `allowedRoots: ["~/Code"]` can't read `/etc/passwd` |


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
- **Buffer-based APIs** — `decryptToBuffer()` and `vault.retrieveBuffer()` return `Buffer` for zeroization; callers MUST `.fill(0)` in `finally`. Prefer over string-returning `decrypt()`/`retrieve()`.
- **`useCredential(vault, serviceId, fn)`** — callback-scoped vault access (`packages/crypto/src/use-credential.ts`). Buffer zeroed in `finally`; credential strings GC-eligible after callback returns. Use this for all new vault access — `decrypt()` and `retrieve()` are deprecated.
- **GWS token injection** — `GOOGLE_WORKSPACE_CLI_TOKEN` env var (not `GOOGLE_ACCESS_TOKEN`); no CLI flags exist. OAuth refresh in `packages/executor/src/tools/gws-auth.ts`.

### Action Categories
Four categories with graduated confirmation: `read` (auto-approve configurable), `write` (confirm), `write-irreversible` (always confirm + "cannot be undone" TUI warning), `dangerous` (always confirm). `write-irreversible` targets email send, calendar invites with attendees, financial transactions. Classifier in `packages/policy/src/classifier.ts`.

### Ed25519 Manifest Signing
- Signing module: `packages/crypto/src/signing.ts` — `generateKeyPair()`, `sign()`, `verify()`
- Signature stored in audit entry, excluded from Merkle hash (signs the hash — circular dependency otherwise)
- `verifyChain(publicKey?)` validates both hash chain AND signatures when public key provided
- Backward compatible: unsigned entries pass verification (unless `strictSignatures: true`)
- Private key stored as `audit-signing.key` (0o600) alongside audit DB — never inside SQLite (co-location nullifies tamper-evidence)

### Bash Sandboxing
- **Interpreter inline-exec** (`python3 -c`, `node -e`, etc.) classified as "dangerous" — always requires confirmation
- firejail not available in Alpine repos — Docker container hardening (`read_only`, `cap_drop: ALL`, `no-new-privileges`) provides defense-in-depth instead

### Content Moderation
- **Mode**: `SENTINEL_MODERATION_MODE=enforce|warn|off` (default: enforce in Docker, warn in local dev)

### GWS Per-Agent Scoping
- `GwsAgentScopes` in `packages/executor/src/tools/gws.ts` — restricts GWS service access per-agent
- `denyServices` checked before `allowedServices` (deny-first, fail-fast)
- No agentId = unrestricted (backward compatible)
- Security audit doc: `docs/security/gws-cli-audit.md`
- Scanner in `packages/executor/src/moderation/scanner.ts`
- Pre-execute: scans request parameters; post-execute: scans tool output
- `enforce`: blocked content returns generic error; `warn`: logged but not blocked

### Input Validation
- **All HTTP endpoints must Zod-validate** — every POST body AND path params through Zod schemas before use. Security review catches missing validation as HIGH severity.

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
All Sentinel actions use typed Zod schemas in `sentinel/manifests/` — see existing schemas for examples.


## Future Work

Details in `docs/plans/path-a-v2-adopt-openfang-primitives.md` and MEMORY.md evaluation queue.

- Phase 2: Google Workspace, OpenClaw agents, CopilotKit/ag-ui
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
| `SENTINEL_GWS_SHA256` | Container | SHA-256 hex digest for GWS binary verification (required in Docker) |
| `SENTINEL_GWS_AGENT_SCOPES` | Container | JSON-encoded per-agent GWS scope map |
| `SENTINEL_GWS_ACCOUNT_EMAIL` | Container | Expected Google account email for identity validation |
| `SENTINEL_AUTH_TOKEN` | Container | Fixed auth token for executor API (auto-generated if unset in Docker) |
| `SENTINEL_TELEGRAM_CHAT_ID` | Container | Telegram chat/user ID for confirmation delivery (optional) |
| `SENTINEL_CONFIRMATION_TIMEOUT_MS` | Container | Client timeout for `/confirm-only` long-polling (default 330000ms) |
| `SENTINEL_VAULT_PASSWORD` | Container | Master password for vault decryption (prompted by `sentinel start`) |
| `SENTINEL_CONFIRM_BASE_URL` | Container | Base URL for confirmation web links (default: localhost:3141, set by Cloudflare tunnel) |

API keys stored in encrypted vault via `sentinel init`. Local dev uses `.dev.vars` (see `.dev.vars.example`). **Never** commit `.dev.vars` with real values.


## Automations

### Hooks (`.claude/settings.json`)
- **PreToolUse**: (1) Rampart daemon — host-level policy firewall on all tools (runs as launchd service, not a Claude hook), (2) `Edit|Write` hook — blocks edits to `.dev.vars`/`.env` files
- **PostToolUse**: Auto-formats `.ts/.tsx` with Biome on every edit

### Skills
- `/security-audit` — Validates all 12 security invariants (run before every commit)
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
- **tsup `--dts` breaks with composite project refs** — All packages use `tsc --build && tsup --format esm` (no `--dts`). Docker build cleans dist/ and uses `tsc -b` only
- **Docker entrypoint** — `packages/executor/src/entrypoint.ts` is the container startup file; `server.ts` only exports `createApp`
- **`noImplicitAnyLet`** — Biome catches `let x;` even when TS allows it; always annotate: `let x: Type;`
- **Executor concurrency** — OpenClaw can spawn parallel agent instances; executor `:3141` must handle concurrent `/execute` POST requests with session-scoped isolation (no shared mutable state between requests)
- **Docker `internal: true`** — agent container cannot reach internet; all LLM calls go through executor's `/proxy/llm/*` endpoint
- **`ANTHROPIC_BASE_URL`** — must be set in agent container to `http://executor:3141/proxy/llm` to route through proxy
- **firejail not in Alpine** — removed from Dockerfile; container hardening (read_only, cap_drop ALL, no-new-privileges) provides equivalent defense-in-depth
- **`SENTINEL_DOCKER=true`** — enables write-file path restriction to `/app/data/`; set in executor container env
- **O_NOFOLLOW + realpath** — `open()` with `O_NOFOLLOW` must target the user-supplied path, not the realpath-resolved path (realpath already resolves symlinks, defeating the check); returns `ELOOP` on macOS, `EMLINK` on some Linux
- **Archived plans** — `docs/plans/archived/` contains superseded Phase 1.5 design docs (TypeScript policy engine approach)
- **Git guardrails false positive** — branch names containing "force" (e.g., `for-confidence`) trigger the force-push hook block; use variable indirection (`branch="..." && git push origin "$branch"`)
- **sqlite-vec KNN syntax** — vec0 requires `WHERE embedding MATCH ? AND k = ?` instead of `ORDER BY distance LIMIT ?`; the extension needs result count upfront for optimized search
- **Worktree dist/ independence** — git worktrees don't share `dist/` with main; workspace deps (e.g., `@sentinel/types`) need manual build in worktree: `npx tsup src/index.ts --format esm`
- **Rampart blocks `.rampart/` writes** — standard policy `block-sensitive-writes` prevents agent from editing `.rampart/policy.yaml`; policy changes are human-only
- **Rampart `**` glob quirk** — `**/path` requires ≥1 path segment; always include bare `path` variant alongside `**/path`
- **Google OAuth tokens in OS Keyring** — GWS CLI stores tokens in macOS Keychain, NOT Sentinel vault; Docker deployment recommended for production (agent can't reach host keyring); local dev should use test/sandbox Google account. See `docs/security/gws-cli-audit.md`
- **Entrypoint ordering** — `entrypoint.ts` must open vault BEFORE `createToolRegistry()` — registry captures vault via closure for GWS token injection
- **Hono test client Content-Length** — Hono's test client doesn't always set Content-Length; body size middleware requiring it must be gated behind `SENTINEL_DOCKER=true`
- **AuditLogger auto-key-gen** — constructor calls `loadOrGenerateSigningKey()`, so ALL entries are signed; tests must use `logger.getSigningPublicKey()` not random keys for verification
- **better-sqlite3 in ESM** — native module uses `require()`; must be `--external` in tsup builds to avoid `Dynamic require of "fs" is not supported` error
- **Node 22 vs 25 ESM strictness** — Node 22 (Docker Alpine) rejects `require()` mixed with top-level `await` (`ERR_AMBIGUOUS_MODULE_SYNTAX`); Node 25 (local) is permissive. Use ESM imports, not `require()`.
- **Docker healthcheck** — BusyBox `wget` fails to connect when executor uses `--secure-heap`; use `node -e "fetch(...)"` instead
- **Docker stale audit.db** — old `audit.db` from earlier phases may lack newer columns (e.g., `agent_id`); delete and let executor recreate
- **CLI data path** — `sentinel init` writes to `data/` relative to project root (resolved via `import.meta.url`), not `process.cwd()`
- **Executor entrypoint ignores `sentinel.json`** — `entrypoint.ts` uses `getDefaultConfig()` (hardcoded), not the config file; all runtime config must come via env vars (`SENTINEL_AUTH_TOKEN`, `SENTINEL_VAULT_PASSWORD`, `SENTINEL_AUDIT_PATH`, `SENTINEL_VAULT_PATH`)
- **Anthropic OAuth banned for third-party apps** — OAuth tokens (`sk-ant-oat01-*`) rejected since Feb 2026; SDK also validates key format client-side (`sk-ant-api03-*` only); must use API key from console.anthropic.com (usage-based billing)
- **Parallel wave contamination** — when multiple waves touch the same file, restore from main first (`git checkout <main-sha> -- <file>`) then apply only the current wave's fix
- **Executor-client HTTP tests need sandbox disabled** — `node:http` createServer with `.listen()` triggers sandbox EPERM; prefer `vi.stubGlobal("fetch", mockFetch)` pattern (see `packages/agent/src/executor-client.test.ts`); only use `dangerouslyDisableSandbox: true` for tests that truly require real TLS handshakes
- **`gwsDefaultDeny` in Docker** — `applyDockerDefaults()` sets `gwsDefaultDeny: true` automatically; agents without a GWS scope entry are **denied**, not warned. Non-Docker mode defaults to `false` (backward compat)
- **Egress proxy HTTPS-only** — `/proxy/egress` rejects HTTP destinations to prevent plaintext credential transmission
- **Placeholder cross-service rejection** — `SENTINEL_PLACEHOLDER_GITHUB_TOKEN` in a request to `api.telegram.org` (bound to service "telegram") is rejected, even if the "github" service exists in vault
- **`openclaw gateway` in Docker** — runs on `sentinel-internal` only; all outbound traffic goes through executor's `/proxy/egress`; `npm install -g openclaw@latest` in Dockerfile stage
- **grammY undici dispatcher** — grammY/OpenClaw use undici's internal HTTP client, not `globalThis.fetch`; HTTPS_PROXY is the only transport mechanism; fetch monkey-patching doesn't work for bundled libraries
- **CONNECT tunnel opacity** — HTTP CONNECT provides domain-level access control but can't inspect request/response content (credential filtering, confirmation interception impossible); `setTimeout(0)` required after tunnel connect for long-polling
- **CONNECT proxy auth** — Uses `Proxy-Authorization: Bearer <token>` header (not standard `Authorization`); `HTTPS_PROXY=http://executor:3141` in gateway container; `NO_PROXY=executor` prevents proxying internal traffic
- **Guard Client SDK** — `@sentinel/guard-client` is zero-dep (uses global `fetch` only); standalone `tsconfig.json` with no package references; any framework can use it without pulling in Sentinel workspace deps
- **`@hono/node-server` `serve()` return** — returns `http.Server` instance; required for `server.on('connect')` handler attachment (CONNECT tunnels bypass Hono router)
- **OpenClaw plugin hooks** — only `before_tool_call`, `tool_result_persist`, `message_sending`, `gateway_stop` are supported; `callback_query`/`update_received` hooks do NOT exist
- **OpenClaw pairing in Docker** — `openclaw pairing approve` must run inside the gateway container: `docker compose exec openclaw-gateway openclaw pairing approve telegram <CODE>`
- **Plugin deployment to host OpenClaw** — after `pnpm build`, must copy `packages/openclaw-plugin/dist/*` to `~/.openclaw/extensions/sentinel/dist/` then `openclaw gateway restart`; stale plugin causes "Aborted" on confirmations
- **Classifier unknown tool default** — unclassified tools default to `write` (confirmation required); add read-like tools (`memory_search`) to `packages/policy/src/rules.ts` `DEFAULT_CLASSIFICATIONS` AND `config/default-classifications.json`
- **Cloudflare tunnel URL parsing** — `cloudflared tunnel --url` prints URL to stderr in `INF +--- https://random.trycloudflare.com ---+` format; PID file at `data/cloudflared.pid`; `sentinel start` auto-starts, `sentinel stop` auto-kills


## Build Progress

| Phase | Tests | PR | Highlights |
|-------|-------|----|------------|
| 0: Local MVP | 163 | — | 7 packages, Docker validated |
| 0.1: Container Hardening | 231 | — | Network lockdown, bash hardening, config freeze, credential filter, moderation |
| 0.2: Make It Usable | 335 | #7 | Bug fixes, confirmation TUI, path whitelist, OWASP gate |
| 1: Harden for Confidence | 490 | #8 | Merkle audit, SSRF, loop guard, rate limiter, PII scrubber, auth, output truncation |
| Memory Store | 542 | #9 | `@sentinel/memory`: SQLite + FTS5 + sqlite-vec, hybrid search, embeddings, consolidation |
| Rampart Integration | — | — | Host-level Rampart firewall v0.8.3, 45 standard + 3 Sentinel project policies, PreToolUse hooks |
| Wave 2.1: Security Primitives | 553 | — | Ed25519 manifest signing, `write-irreversible` category, irreversible TUI warning |
| Wave 2.2: GWS CLI + Email Defense | 583 | — | GWS tool integration, email injection scanner, per-agent scoping, credential zeroization (G1-G8), Docker hardening |
| GWS Credential Audit | 594 | — | Closed 5 audit gaps: LLM proxy body filtering, PEM key detection, exfiltration patterns, outbound email credential gate, OS Keyring docs |
| Wave 2.2b: Credential Zeroization | 652 | #16 | `useCredential()` helper, V8 string lifetime minimization, LLM proxy refactor, GWS vault migration, API deprecation |
| Wave 2.2c: Pen Test Fixes | 847 | #17 | 16 pen test findings + 16 PR review fixes (3 critical, 8 important, 5 additional): fail-safe limits, HMAC wiring, TOCTOU inode, Ed25519 key separation, body size limits, Rust N-API scaffold |
| Wave 2.3a: OpenClaw Plugin | 895 | — | `/classify` + `/filter-output` endpoints, `@sentinel/openclaw-plugin` package, `delegate.code` handler, delegation queue, `sentinel setup openclaw` CLI, heartbeat monitor, setup guide |
| Wave 2.3b: E2E Integration Tests | 903 | — | Plugin ↔ executor pipeline, delegation lifecycle, shared audit sources, fail-closed health monitor, sanitizeOutput |
| Wave 2.3c: GWS Security Guardrails | 1106 | — | Docker GWS defaults (G2), fail-closed plugin (G3), account email validation (G4), gwsDefaultDeny (G5), E2E injection test (G6), vault failure logging (G7), test mock refactoring (G8) |
| Wave 2.4: Plugin Wiring + Egress Proxy | 716 | #32 | register.ts adapter, /confirm-only endpoint, egress proxy, ag-ui SSE confirmation stream, web approval page, HMAC URL tokens, Cloudflare tunnel |
| Guard SDK + CONNECT Proxy | — | — | `@sentinel/guard-client` SDK (23 tests), CONNECT tunnel proxy handler (22 tests), Docker HTTPS_PROXY wiring, gateway entrypoint prep |

### Backlog

#### Infrastructure & Integration
- [ ] Create a google workspace account for openclaw
- [ ] Plano model routing — GPT latest + fallbacks to Claude Opus, Gemini Flash Lite 3.1; reference [Claude chat 1](https://claude.ai/share/d7e9dbba-dec4-4f28-a3b7-b9920b76bd10), [Claude chat 2](https://claude.ai/share/c67fb5e7-eb4b-4356-be0e-d7ce66dd359c), [OpenAI model docs](https://developers.openai.com/api/docs/guides/latest-model)
- [ ] CopilotKit integration — dedicated chatbot use case + AI learning prototype; ag-ui evaluation for MCP app integration; A2A for multi-agent orchestration
- [ ] Write-action HITL via ag-ui — replace TUI confirmation with rich ag-ui frontend
- [ ] UCP integration — unified context protocol via ag-ui + CopilotKit
- [ ] Google Model Armor — add to executor content moderation pipeline
- [ ] Research: Reddit security warning, ClawMetry review
- [ ] Claude Code integrations and heartbeats for coding tasks via notes
- [ ] Promptfoo for evals and red teaming (pen testing, adversarial attacks): https://github.com/promptfoo/promptfoo#readme
- [ ] Posthog for app analytics: https://posthog.com/
- [ ] Moltworkers CF deployment: (https://blog.cloudflare.com/moltworker-self-hosted-ai-agent/) | (https://github.com/cloudflare/moltworker)
- [ ] Paperclip: Open-source orchestration for zero-human companies | https://github.com/paperclipai/paperclip

### References
- See `docs/plans/path-a-v2-adopt-openfang-primitives.md` §Phase 2 for security gaps and agent roster.
- See openclaw repo: https://github.com/openclaw/openclaw

#### Google Workspace Security References
- [Work Safer with Google Workspace](https://workspace.google.com/security/)
- [Google Security Blog: Mitigating Prompt Injection Attacks](https://security.googleblog.com/2025/06/mitigating-prompt-injection-attacks.html)
- [Google's Approach for Secure AI Agents](https://research.google/pubs/an-introduction-to-googles-approach-for-secure-ai-agents/)
- [Zero Trust Security](https://workspace.google.com/security/zero-trust/)
- [Enterprise Security Controls for Gemini in Workspace](https://workspace.google.com/blog/ai-and-machine-learning/enterprise-security-controls-google-workspace-gemini)

#### Notes from Mar. 15

★ Insight from https://openai.com/index/equip-responses-api-computer-environment/
OpenAI independently validated Sentinel's core architecture. Their "Equip" system (Responses API + Shell Tool + Container Runtime) is structurally the same two-process model we built: model proposes → platform executes → secrets never visible to model. Their "auth-translation sidecar" is functionally equivalent to our executor's useCredential() vault injection. Sentinel is actually ahead in several areas (encrypted vault vs env vars, Merkle audit chain vs simple logging, HITL confirmation vs none, zero-outbound-by-default vs allowlist).

The real gap isn't architectural — it's operational. OpenClaw currently calls /classify for policy decisions but executes auto_approve tools itself, bypassing Sentinel's audit, credential filtering, SSRF protection, and PII scrubbing. OpenAI routes ALL commands through the platform — no bypass path exists. We need to match that.

One good idea to steal: domain-scoped credential binding. OpenAI binds secrets to specific destination domains — the sidecar only injects a credential if the outbound request matches the credential's allowed domain. We have service-keyed vault entries but no egress domain binding.
───────────────────────────────

The plan identifies 3 priorities:

Route ALL OpenClaw execution through Sentinel (critical — classification without enforcement is a firewall that logs but doesn't block)
Domain-scoped credential binding (defense-in-depth from OpenAI's design)
Execution result passthrough (make the plugin return Sentinel's filtered output as OpenClaw's tool result)