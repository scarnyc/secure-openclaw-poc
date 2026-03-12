# Sentinel — Secure Agent Runtime

Sentinel is a security-hardened agent runtime with process isolation between the agent (untrusted) and executor (trusted). Local-first, runs on Mac Mini via Docker Compose.

## Current Phase: Phase 2 — Integrations + Real Agents

**Roadmap**: `docs/plans/path-a-v2-adopt-openfang-primitives.md`
**Wave spec**: `docs/superpowers/specs/2026-03-10-phase-2-waves-design.md`

**Phase 1 completed** (PR #8, 490 tests). **Memory store** (PR #9, 542 tests). **Phase 2** decomposes into 4 waves.

**Wave Progress**
- [x] Wave 2.1: Security Primitives — Ed25519 signing + irreversible classification (553 tests)
- [x] Wave 2.2: Google Workspace CLI + Email Defense (583 tests)
- [x] Wave 2.2b: Credential Zeroization — useCredential helper, V8 string lifetime minimization (652 tests)
- [ ] Wave 2.3: OpenClaw + Sentinel Plugin
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
pnpm test         # Run all tests (652+)
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
| `.claude/skills/security-audit/SKILL.md` | `/security-audit` skill — validates 12 security invariants |
| `.claude/skills/upstream-sync/SKILL.md` | `/upstream-sync` skill — rebase on moltworker (user-only) |
| `.rampart/policy.yaml` | Host-level Rampart firewall policy (tfstate, data protection, security code gate) |


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
├── .rampart/                    # Rampart project policy (host-level firewall)
├── packages/                    # MVP code (pnpm workspace)
│   ├── types/                   # Shared types + Zod schemas
│   ├── crypto/                  # Credential vault (AES-256-GCM) + Ed25519 signing
│   ├── policy/                  # Deterministic action classifier
│   ├── audit/                   # Append-only SQLite audit log
│   ├── executor/                # Trusted process (Hono :3141)
│   ├── agent/                   # Untrusted process (LLM loop)
│   ├── cli/                     # Host orchestrator + TUI
│   └── memory/                  # Hybrid retrieval memory store (SQLite + FTS5 + sqlite-vec)
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
- Backward compatible: unsigned entries pass verification

### Bash Sandboxing
- **Interpreter inline-exec** (`python3 -c`, `node -e`, etc.) classified as "dangerous" — always requires confirmation
- **firejail** wrapping when `SENTINEL_BASH_SANDBOX=firejail` — `--net=none --private` for defense-in-depth
- firejail is Linux-only; local Mac dev falls back to unsandboxed execution

### Content Moderation
- **Mode**: `SENTINEL_MODERATION_MODE=enforce|warn|off` (default: warn)

### GWS Per-Agent Scoping
- `GwsAgentScopes` in `packages/executor/src/tools/gws.ts` — restricts GWS service access per-agent
- `denyServices` checked before `allowedServices` (deny-first, fail-fast)
- No agentId = unrestricted (backward compatible)
- Security audit doc: `docs/security/gws-cli-audit.md`
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
- **Git guardrails false positive** — branch names containing "force" (e.g., `for-confidence`) trigger the force-push hook block; use variable indirection (`branch="..." && git push origin "$branch"`)
- **sqlite-vec KNN syntax** — vec0 requires `WHERE embedding MATCH ? AND k = ?` instead of `ORDER BY distance LIMIT ?`; the extension needs result count upfront for optimized search
- **Worktree dist/ independence** — git worktrees don't share `dist/` with main; workspace deps (e.g., `@sentinel/types`) need manual build in worktree: `npx tsup src/index.ts --format esm`
- **Rampart blocks `.rampart/` writes** — standard policy `block-sensitive-writes` prevents agent from editing `.rampart/policy.yaml`; policy changes are human-only
- **Rampart `**` glob quirk** — `**/path` requires ≥1 path segment; always include bare `path` variant alongside `**/path`
- **Google OAuth tokens in OS Keyring** — GWS CLI stores tokens in macOS Keychain, NOT Sentinel vault; Docker deployment recommended for production (agent can't reach host keyring); local dev should use test/sandbox Google account. See `docs/security/gws-cli-audit.md`
- **Entrypoint ordering** — `entrypoint.ts` must open vault BEFORE `createToolRegistry()` — registry captures vault via closure for GWS token injection


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
