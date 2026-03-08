# Plan: Path A — Continue Sentinel, Adopt OpenFang's Primitives (v2)

## Context

Sentinel has 7 packages, 231 tests, and a working 8-stage execution pipeline. But it's **not usable today** — the base64 credential regex catches real output, `sh -c`/`bash -c` bypass dangerous classification, there's no confirmation UI, and local dev has no path restrictions. OpenFang analysis revealed 28 security features (not 16), several of which Sentinel should adopt.

This plan reorganizes around **usability milestones**: what's needed to actually run an agent safely, not what's theoretically most secure.

### Research Findings

**OpenFang features Sentinel should adopt** (newly discovered):
- Loop guard with ping-pong detection (SHA-256 hash of tool+params, 30-item history, Allow→Warn→Block→CircuitBreak escalation, backoff scheduling)
- Capability inheritance (child agents can't exceed parent capabilities)
- Context budget enforcement (30% per-result cap, 75% global cap)
- Tool recursion depth limiting (max depth 5)
- Constant-time token comparison (timing-attack resistant)
- Request UUID logging (structured correlation)
- Subprocess output truncation (50KB shell, 10MB HTTP)

**Secret zeroization in Node.js — what it actually provides:**

The vulnerability is concrete. Currently:
- `encryption.ts:decrypt()` returns `string` — V8 strings are immutable, can't be zeroed, GC timing is unpredictable
- `llm-proxy.ts` reads API keys from `process.env` — keys exist as V8 strings for the **entire process lifetime** (hours/days)
- Attack vectors on Mac Mini: `lldb -p <pid>` memory dump, core dump files, macOS swap file (`/private/var/vm/swapfile*`), `fork()` inheritance to bash child processes

What `Buffer.fill(0)` changes:
- `Buffer` is backed by `ArrayBuffer`, which is NOT compacted by V8 GC — it lives at a fixed memory address
- `Buffer.fill(0)` zeroes the actual underlying memory immediately, deterministically
- The architectural shift: remove API keys from `process.env` entirely → decrypt from vault per-request as `Buffer` → use → zero in `finally` block
- Exposure window goes from **process lifetime** (hours) to **single HTTP request + GC cycle** (milliseconds)

Honest limitation:
- The `toString('utf-8')` call at HTTP header creation produces a V8 `string` copy we can't zero
- Node's `fetch()` internals and OpenSSL make additional copies during TLS
- These are short-lived and GC-eligible immediately — vastly better than `process.env` persistence
- ~20 lines of changes in `encryption.ts` and `llm-proxy.ts`

**`isolated-vm` sandbox timing:**
- Current tools (bash, file ops, HTTP) don't run arbitrary JavaScript
- A JS sandbox doesn't intercept child processes or fs calls
- Becomes critical when OpenClaw skills add arbitrary JS execution
- Correct phasing: concurrent with OpenClaw setup, not before

**Bugs found in current codebase:**
1. `credential-patterns.ts` generic base64 regex `/[A-Za-z0-9+/=]{40,}/g` — catches real output (build hashes, logs)
2. `bash-parser.ts` missing `sh -c` and `bash -c` — classified as safe, should be dangerous
3. No local path whitelist — `SENTINEL_DOCKER=true` required for path restrictions, not set locally
4. Symlink race in `write-file.ts` — `realpath(...).catch(() => resolve(...))` between check and write
5. No working confirmation UX — endpoint exists (`/confirm/:manifestId`) but no terminal UI

---

## Phasing: What's Critical → Deferred → Nice-to-Have

### Phase 0: Make It Usable (3-5 days)

**Goal**: Fix bugs and gaps that prevent actual use. After this phase, you can run an agent through Sentinel on your Mac Mini.

| Task | Why Critical | LOE | Files |
|------|-------------|-----|-------|
| Fix base64 credential regex | Catches real output, makes tool responses unusable | 30 min | `packages/types/src/credential-patterns.ts` |
| Add `sh -c`, `bash -c` to dangerous detection | Trivial bypass for all bash deny-list rules | 1 hr | `packages/policy/src/bash-parser.ts` |
| Simple terminal confirmation prompt | Can't approve/deny dangerous actions without it | 4 hr | `packages/cli/src/confirmation-tui.ts` (new) |
| Local path whitelist (`allowedRoots`) | Local dev can write anywhere — no file protection | 2 hr | `packages/executor/src/path-guard.ts` |
| Fix symlink race in write-file | Path escape via TOCTOU race | 1 hr | `packages/executor/src/tools/write-file.ts` |
| Secret zeroization convention | API keys linger in V8 heap indefinitely | 1 hr | `packages/crypto/src/encryption.ts`, `packages/executor/src/llm-proxy.ts` |
| End-to-end smoke test | No way to verify the system works | 2 hr | new test file |
| Document local dev setup | Can't start without reading source code | 1 hr | update CLAUDE.md + `.dev.vars.example` |

**Deliverable**: `docker compose up` → send a bash command → see confirmation prompt → approve → get result → verify audit log entry. All without false-positive credential redaction.

### Phase 1: Harden for Confidence (2-3 weeks)

**Goal**: Security patterns that catch real attacks. After this phase, you trust Sentinel enough to run it unattended.

| Task | What It Does | LOE | Files |
|------|-------------|-----|-------|
| Merkle hash-chain audit | Tamper-evident logging — detect if anyone modifies audit records | 2 hr | `packages/audit/src/logger.ts` (+25 lines, `node:crypto`) |
| SSRF protection | Block LLM proxy requests to private IPs/localhost/cloud metadata | 2 hr | `packages/executor/src/ssrf-guard.ts` (new, ~40 lines) |
| Loop guard | Detect agent retry storms and ping-pong patterns, escalate to circuit break | 4 hr | `packages/policy/src/loop-guard.ts` (new, ~60 lines) |
| GCRA rate limiter | Per-agent rate limiting on `/execute` endpoint | 1 hr | `packages/policy/src/rate-limiter.ts` (new, ~25 lines) |
| Bash deny-list additions | `rm -rf /`, `rm -rf ~`, `rm -rf $HOME`, mail/email commands | 1 hr | `packages/executor/src/tools/bash.ts` |
| PII scrubber | SSN, phone, email, salary, LinkedIn/GitHub URL redaction | 4 hr | `packages/executor/src/pii-scrubber.ts` (new, ~80 lines) |
| Constant-time token comparison | Timing-attack resistant API key validation | 30 min | `packages/executor/src/server.ts` (`crypto.timingSafeEqual`) |
| Request UUID logging | Structured correlation IDs for debugging | 1 hr | `packages/executor/src/server.ts` (middleware) |
| Output truncation | Cap bash output at 50KB, HTTP at 10MB (prevent memory exhaustion) | 1 hr | `packages/executor/src/tools/bash.ts` |
| Invariant tests (G7-G12) | Tests for Merkle, SSRF, rate limit, PII, loop guard, path whitelist | 4 hr | test files per feature |
| claude-mem setup + hardening | Set up claude-mem (port 37777, SQLite + FTS5), apply Sentinel validation: Zod schemas, credential stripping, size caps, blocked categories | 3 days | `sentinel/mem-hardening/` |
| Rampart evaluation | Install Rampart, test equivalent policies (YAML vs Zod), measure overlap with Sentinel classification + credential filter | 4 hr | evaluation doc |

**New invariants after Phase 1:**

| # | Invariant | Test |
|---|-----------|------|
| 7 | Merkle chain tamper-evident | Modified audit row detected by `verifyChain()` |
| 8 | SSRF blocked | Private IPs / localhost / 169.254.x rejected |
| 9 | Per-agent rate limiting | Burst exceeding rate gets 429 |
| 10 | PII scrubbed from outbound | SSN in tool output → `[REDACTED]` |
| 11 | Loop guard blocks storms | >N identical calls in M seconds → blocked |
| 12 | Per-agent path whitelist | Agent with `allowedRoots: ["~/Code"]` can't read `/etc/passwd` |

### Phase 2: Integrations + Real Agents (4-6 weeks)

**Goal**: Connect to real-world services, enable OpenClaw → Claude Code delegation, and run multiple agents. After this phase, you have a personal AI platform where autonomous agents can delegate coding tasks.

| Task | What It Does | LOE |
|------|-------------|-----|
| Google Workspace CLI integration | Gmail, Calendar, Drive as MCP tool sources | 1 week |
| Analyze how to setup OpenClaw with sentinel & complete OpenClaw setup + `isolated-vm` sandbox | Parallel agent spawning; user-authored skills run in V8 isolates | 1 week |
| `delegate.code` manifest + CLI handler | OpenClaw proposes coding task → Sentinel confirms → CLI spawns Claude Code in worktree | 3 days |
| Heartbeat scheduled task | Every 5 min: checks if Claude Code sessions alive, restarts dead ones, notifies on PR creation | 2 days |
| Nightly consolidation task | 2 AM cron: reviews audit log, extracts learnings, updates claude-mem | 1 day |
| Agent roster deployment | 16 agents, 4 sensitivity tiers (Normal/High/Critical) | 3 days |
| System prompt authoring (soul.md) | Write agent system prompts using Claude/Claude Code best practices — reference Anthropic's `soul.md` and constitutional AI principles for tone, safety boundaries, role definition, and behavioral constraints per sensitivity tier | 2 days |
| Per-agent MCP scope restrictions | Job agent only sees "Job Search" emails | 3 days |
| Irreversible action classification | Send email / calendar invite = higher confirmation threshold | 2 days |
| Email prompt injection defense | All email bodies treated as untrusted input | 2 days |
| Ed25519 manifest signing | Non-repudiation for audit trail forensics | 2 hr |
| Capability inheritance | Child agents can't exceed parent capabilities | 2 hr |
| Context budget enforcement | Per-result 30% cap, global 75% cap | 2 hr |
| Tool recursion depth limiting | Max depth 5 for agent-to-agent calls | 30 min |
| sqlite-vec integration | Embedding model selection, `vec0` table schema, hybrid FTS5+vec0 query strategy, embedding pipeline at observation write time | 3 days |
| Plano model routing | GPT latest + fallbacks to Claude Opus, Gemini Flash Lite 3.1; route by task complexity/cost | 2 days |
| Prompt caching (all 3 providers) | Enable prompt caching with Anthropic (cache_control), OpenAI (automatic), and Gemini (cachedContent) — reduce latency + cost for repeated system/tool prompts via LLM proxy | 1 day |
| Google Model Armor evaluation | Test free tier, evaluate cloud-grade injection detection vs. local Sentinel controls, measure latency impact on LLM proxy | 4 hr |

**OpenClaw → Claude Code delegation flow:**

```
OpenClaw Agent (Docker, untrusted)
    │ manifest: { tool: "delegate.code", task: "PRD content", worktree: "feature-xyz" }
    ▼
Sentinel Executor (Docker, trusted)
    │ classifies as "dangerous" → routes to confirmation
    ▼
Confirmation TUI / CLI (HOST, trust anchor)
    │ user approves → CLI spawns Claude Code:
    │   claude -p "$(cat prd.md)" --worktree feature-xyz \
    │     --output-format json --allowedTools "Read,Write,Edit,Bash,Glob,Grep" \
    │     --max-budget-usd 5.0
    │   env: PRODUCTIVITYHUB_BATCH=1  (suppresses stop hooks)
    ▼
Claude Code (HOST, isolated worktree)
    │ PreToolUse hook → curl POST /classify (audit + classification)
    │ PostToolUse hook → curl POST /filter-output (credential + PII filter)
    │ Optional: /ralph-loop for iterative dev until completion
    │ Creates PR when done
    ▼
Heartbeat Cron (every 5 min)
    │ checks: process alive? new commits? PR created?
    │ dead → restart; PR created → notify OpenClaw agent
    ▼
OpenClaw Agent ← completion signal ← reviews PR
```

**Why CLI is the spawn point (not Docker executor)**: Executor runs in Docker — cannot spawn host processes without mounting Docker socket (security anti-pattern). CLI already runs on host, manages Docker containers, has filesystem access. It's the natural trust anchor for spawning Claude Code.

**Heartbeat / consolidation system (maps to Felix/Nat pattern):**

| Felix Pattern | Sentinel Implementation |
|--------------|------------------------|
| Daily notes (track active projects) | Audit log + `~/.claude/scheduled-tasks/` state files |
| Heartbeat (check sessions alive, restart dead) | `create_scheduled_task("heartbeat", "*/5 * * * *", ...)` |
| Nightly consolidation (review day, update knowledge) | `create_scheduled_task("consolidate", "0 2 * * *", ...)` |
| Ralph Loops (iterative dev until completion) | `/ralph-loop "task" --max-iterations N --completion-promise "DONE"` |
| PRD → Codex delegation | PRD → `delegate.code` manifest → Claude Code in worktree |

### Phase 2.5: Claude Code Integration (2 weeks)

**Goal**: Sentinel secures Claude Code the same way it secures OpenClaw. After this phase, both your coding agent and your autonomous agents share the same security pipeline.

**Why a separate phase**: Claude Code runs directly on the host (not in Docker). It has its own hooks system and MCP server connections. The integration is architectural — hooks + MCP proxy — not a rewrite.

**The gap today**: OpenClaw agents go through Sentinel's 8-stage pipeline (validation → classification → moderation → confirmation → execution → credential filter → PII scrub → audit). Claude Code gets **none of this** — no audit log, no credential filtering on MCP responses, no PII scrubbing, no rate limiting.

**Integration architecture**:

```
┌──────────────────────┐          ┌──────────────────────────────┐
│   CLAUDE CODE         │          │      SENTINEL EXECUTOR        │
│   (host process)      │          │      (Docker or host)         │
│                       │ PreTool  │                               │
│   PreToolUse hook ────┼──curl──►│  POST /classify                │
│   PostToolUse hook ───┼──curl──►│  POST /filter-output           │
│                       │          │  - Classification             │
│   MCP connections:    │          │  - Audit logging              │
│   ┌─────────────────┐ │          │  - Rate limiting              │
│   │ Granola MCP     │◄┼── via ──┤  - Loop guard                  │
│   │ Indeed MCP      │ │ Sentinel│  - Credential filter           │
│   │ Slack MCP       │ │ MCP     │  - PII scrubber                │
│   └─────────────────┘ │ proxy   │  - Content moderation          │
└──────────────────────┘          └──────────────────────────────┘
```

**A. Hooks → Sentinel HTTP API** (for all tool types):
- PreToolUse: shell script `curl`s to `POST /classify` with tool name + input → Sentinel classifies (safe/confirm/block), logs to audit, checks rate limit + loop guard
- PostToolUse: shell script `curl`s to `POST /filter-output` with tool output → Sentinel strips credentials, scrubs PII, logs

**B. Sentinel MCP proxy** (for sensitive MCP servers):
- Claude Code connects to Sentinel's MCP-compatible endpoint instead of raw Gmail/Calendar/Slack MCP servers
- Sentinel forwards to the real MCP server after applying: scope restrictions, credential filtering, PII scrubbing, content moderation, audit logging
- Same pattern as the existing LLM proxy but for MCP tools

| Task | What It Does | LOE |
|------|-------------|-----|
| `POST /classify` endpoint | Accepts tool name + input from any source (OpenClaw or Claude Code), returns decision, logs to audit | 3 hr |
| `POST /filter-output` endpoint | Accepts tool output, applies credential filter + PII scrubber, returns sanitized output | 2 hr |
| PreToolUse hook script | Shell script: sends all Claude Code tool calls to Sentinel for classification + audit | 2 hr |
| PostToolUse hook script | Shell script: sends tool output to Sentinel for credential/PII filtering | 2 hr |
| MCP proxy server | Sentinel exposes MCP-compatible endpoints wrapping Gmail/Calendar/Slack with full policy enforcement | 1 week |
| Claude Code scope config | Per-session or per-project tool scope restrictions (which MCP tools Claude Code can access) | 2 days |
| Shared audit schema | `source: "openclaw" | "claude-code"` column in audit log — both write to same Merkle-chained DB | 1 hr |
| Integration tests | Verify hooks → executor → audit pipeline end-to-end for Claude Code | 4 hr |

**Permission model comparison:**

| Capability | OpenClaw via Sentinel | Claude Code Today | Claude Code + Sentinel |
|-----------|---------------------|------------------|----------------------|
| Action classification | 3-tier (safe/confirm/block) | settings.json allow list + user prompt | 3-tier via PreToolUse hook |
| Credential filtering | Executor strips from responses | None | PostToolUse hook → executor filter |
| PII scrubbing | Executor scrubs outbound | None | PostToolUse hook + MCP proxy |
| Audit logging | SQLite + Merkle chain | None | PreToolUse hook logs to executor |
| Rate limiting | GCRA per-agent | None | Classify endpoint checks limits |
| Loop guard | SHA-256 dedup + escalation | None | Classify endpoint tracks history |
| Path restrictions | allowedRoots | `.env` edit block only | Classify checks path-guard |
| MCP scope restrictions | Per-agent tool allowlists | Full access to all MCP tools | MCP proxy enforces scope |
| Content moderation | Pre/post-execute scan | None | MCP proxy scans |
| Bash sandboxing | firejail + deny-list | git-guardrails.sh only | Classify checks deny-list + parser |

### Phase 3: Data Governance (4-6 weeks, defer safely)

**Goal**: Multi-agent data isolation for sensitive domains. Only needed when running Critical-tier agents (financial, health, legal).

| Task | What It Does |
|------|-------------|
| Domain-scoped memory isolation | Health ≠ financial ≠ legal memory partitions |
| Financial transaction safety | Amount thresholds, cooling periods |
| Outbound data classification | Scrub PII from agent-generated emails/posts |
| Taint tracking (compile-time) | `Tainted<T>` / `Clean<T>` branded types |
| Audit log encryption at rest | SQLite with sensitive data is itself a target |
| RBAC capability gates | 4-tier role hierarchy (Viewer/User/Admin/Owner) |
| Session repair | 7-phase message history validation |
| CopilotKit / ag-ui frontend | Replace TUI confirmation with rich web UI — ag-ui for streaming agent state, CopilotKit for generative UI | Evaluate |
| UCP integration | Unified context protocol via ag-ui + CopilotKit for cross-agent context sharing | Evaluate |
| A2A protocol evaluation | Google Agent-to-Agent protocol vs. OpenClaw skills binding model for multi-agent orchestration | Evaluate |

---

## Phase Gates: OWASP Security Review

Each phase ends with an OWASP Top 10 review as a **gate approval step** — work does not proceed to the next phase until the review passes. This is not a feature; it's a quality gate.

| Gate | Scope | What It Covers |
|------|-------|---------------|
| **Post-Phase 0** | Executor API surface | Injection (A03), broken access control (A01), security misconfiguration (A05) — focus on the `/execute`, `/confirm`, `/proxy/llm` endpoints |
| **Post-Phase 1** | New security primitives | SSRF guard (A10: SSRF), rate limiter (brute force), Merkle audit (A09: logging failures), PII scrubber (A02: crypto failures for data at rest) |
| **Post-Phase 2** | Integration surfaces | MCP tool proxies, OpenClaw delegation flow, Google Workspace API surface — focus on injection via email/calendar content (A03), broken auth on new endpoints (A07) |
| **Post-Phase 2.5** | Claude Code hook pipeline | Hook-to-executor HTTP path (A01: access control), classify/filter endpoints (A03: injection), MCP proxy auth (A07), audit completeness (A09) |
| **Post-Phase 3** | Data governance | Encryption at rest (A02), RBAC enforcement (A01), domain isolation boundaries, taint tracking validation |

**Process**: Run `/security-audit` skill + manual OWASP checklist review. Document findings in `docs/owasp-reviews/phase-N.md`. Critical/High findings block phase completion; Medium findings get tracking issues.

---

## External Security Tools: Evaluation

### Google Model Armor — Runtime Security for Agentic AI

**What it is**: A Google Cloud managed service providing runtime security guardrails for AI agents. NOT content moderation — it's an in-line security layer that intercepts agent prompts and responses.

**Capabilities**:
- In-line protection against prompt injection, jailbreaking, and sensitive data leakage for agent interactions
- Specialized posture controls for AI agents (security policies, organizational standards)
- Threat detection for AI agents using Mandiant + Google frontline intelligence
- Automated discovery of AI agents and MCP servers (inventory + risk identification)
- Multi-model support — unified guardrails across Gemini, OpenAI, and third-party models on Vertex AI

**Relationship to Sentinel**: Model Armor provides cloud-grade versions of several Sentinel components:
| Sentinel Component | Model Armor Equivalent |
|-------------------|----------------------|
| Content moderation scanner | In-line prompt/response protection |
| Credential filter | Sensitive data leakage prevention |
| Classification pipeline | Runtime guardrails + posture controls |
| Agent roster | Agent inventory + MCP server discovery |

**Phase placement**: Evaluate in **Phase 2** (when Google Workspace integration requires GCP anyway). Model Armor can wrap Sentinel's LLM proxy calls with cloud-grade detection as a defense-in-depth layer — local Sentinel controls remain the primary enforcement, Model Armor adds managed intelligence (Mandiant threat data, ML-based injection detection) that's impractical to build locally.

**Decision point**: Cost vs. value. Free tier may cover personal use. If cost-prohibitive, Sentinel's local controls are sufficient for the Mac Mini threat model.

### Rampart — Go-Based AI Agent Firewall

**What it is**: Open-source Go binary (`go install github.com/peg/rampart@latest`) that operates as a policy engine intercepting agent commands, file access, and network requests before execution.

**Capabilities**:
- YAML-defined policy rules with 4 response types: `deny`, `ask` (human approval), `watch` (log), `allow`
- Native Claude Code integration via `~/.claude/settings.json` hooks
- Response scanning to prevent credentials reaching agent context
- Hash-chained audit trail
- Multi-agent support: Claude Code, Cline, Codex CLI, OpenClaw
- System-level interception via LD_PRELOAD, shell wrapping, MCP proxy
- Live monitoring dashboard (`rampart watch`)
- Hot-reloading of policies on file changes

**Relationship to Sentinel**: Rampart overlaps significantly with Sentinel's classification + credential filter + audit. Key comparison:
| Concern | Sentinel | Rampart |
|---------|----------|---------|
| Policy format | Zod TypeScript schemas | YAML config files |
| Runtime | Node.js (embedded in executor) | Go binary (external process) |
| Interception | HTTP middleware in executor | LD_PRELOAD, shell wrapping, hooks |
| Audit | SQLite + Merkle chain | Hash-chained log |
| Credential filter | Regex patterns in TypeScript | Response scanning |
| Scope | Purpose-built for Sentinel 2-process model | Generic across any AI agent |

**Phase placement**: Evaluate in **Phase 1** (when hardening). Two possible adoption paths:
1. **Complement**: Use Rampart as defense-in-depth alongside Sentinel — Rampart at system/shell level, Sentinel at application level
2. **Phase 2.5 shortcut**: Use Rampart's native Claude Code hooks instead of building custom `sentinel-classify.sh` / `sentinel-filter.sh` scripts — Rampart already does this

**Decision point**: Does Rampart's YAML policy model meet Sentinel's needs, or does Sentinel's Zod-typed TypeScript pipeline provide stronger guarantees? Test by writing equivalent policies in both and comparing coverage.

---

## Critical Files to Modify

### Phase 0

| File | Change |
|------|--------|
| `packages/types/src/credential-patterns.ts` | Fix generic base64 regex — make provider-specific or raise threshold to 50+ chars |
| `packages/policy/src/bash-parser.ts` | Add `sh -c`, `bash -c`, `zsh -c` to interpreter inline-exec detection |
| `packages/executor/src/tools/write-file.ts` | Fix symlink TOCTOU race — use `O_NOFOLLOW` or atomic check+write |
| `packages/executor/src/path-guard.ts` | Exists but needs local dev mode (not just `SENTINEL_DOCKER=true`) |
| `packages/crypto/src/encryption.ts` | Return `Buffer` from decrypt, never `string` |
| `packages/executor/src/llm-proxy.ts` | Use `Buffer` for API keys, `fill(0)` in `finally` |
| `packages/cli/src/confirmation-tui.ts` | New — simple readline-based approve/deny prompt |

### Phase 1

| File | Change |
|------|--------|
| `packages/audit/src/logger.ts` | Add `prev_hash` + `entry_hash` columns, `computeEntryHash()`, `verifyChain()`, wrap in `db.transaction()` |
| `packages/executor/src/ssrf-guard.ts` | New — `dns.resolve4/6` → reject private ranges |
| `packages/policy/src/loop-guard.ts` | New — SHA-256 hash of (tool, params), 30-item history, escalation levels |
| `packages/policy/src/rate-limiter.ts` | New — GCRA with TAT map, ~25 lines |
| `packages/executor/src/pii-scrubber.ts` | New — regex patterns for SSN, phone, email, salary |
| `packages/executor/src/server.ts` | Add `crypto.timingSafeEqual` for bearer auth, UUID middleware |
| `packages/executor/src/router.ts` | Wire new stages: rate limiter → loop guard → SSRF → PII scrub |

### Phase 2

| File | Change |
|------|--------|
| `sentinel/manifests/delegate-code.ts` | New — Zod schema for `delegate.code` manifest (task, worktree, model, budget, allowedTools, maxIterations) |
| `packages/cli/src/delegate-handler.ts` | New — receives confirmed delegation, spawns `claude -p ... --worktree ... --output-format json` with `PRODUCTIVITYHUB_BATCH=1` |
| `packages/cli/src/heartbeat.ts` | New — checks active Claude Code sessions: process alive? new commits? PR created? Restarts dead sessions. |
| `packages/cli/src/consolidation.ts` | New — nightly audit log review, extract learnings, update claude-mem |
| `~/.claude/scheduled-tasks/heartbeat/SKILL.md` | New — scheduled task: `"*/5 * * * *"` heartbeat cron |
| `~/.claude/scheduled-tasks/consolidate/SKILL.md` | New — scheduled task: `"0 2 * * *"` nightly consolidation |

### Phase 2.5

| File | Change |
|------|--------|
| `packages/executor/src/classify-endpoint.ts` | New — `POST /classify` accepts tool name + input, returns decision, logs to audit |
| `packages/executor/src/filter-endpoint.ts` | New — `POST /filter-output` accepts output, applies credential + PII filters |
| `.claude/hooks/sentinel-classify.sh` | New — PreToolUse hook script: `curl` to `/classify` endpoint |
| `.claude/hooks/sentinel-filter.sh` | New — PostToolUse hook script: `curl` to `/filter-output` endpoint |
| `packages/executor/src/mcp-proxy.ts` | New — MCP-compatible proxy wrapping upstream MCP servers with policy enforcement |
| `packages/audit/src/logger.ts` | Add `source` column: `"openclaw" \| "claude-code"` to distinguish audit entries |
| `packages/executor/src/server.ts` | Wire classify + filter endpoints, mount MCP proxy routes |

---

## What OpenFang Has That We Deliberately Skip

| Feature | Why Skip |
|---------|----------|
| WASM dual-metered sandbox | Current tools don't run arbitrary JS. Docker isolates processes. `isolated-vm` added with OpenClaw in Phase 2. |
| 27 LLM providers | We use 3 (Anthropic, OpenAI, Gemini). Add more via LLM proxy config, not provider SDKs. |
| 40 channel adapters | Not needed — personal Mac Mini use, not multi-channel bot |
| Skill marketplace | Tools are executor-controlled, not user-installable |
| Tauri desktop app | TUI → ag-ui frontend (Phase 2+) |
| OFP mutual HMAC-SHA256 | Local Docker — no P2P networking needed |
| Session repair (7-phase) | Phase 3 — not needed until running unattended for hours |
| Secret zeroization (Rust-grade) | V8 can't zero the `toString()` copy used for HTTP headers, or internal copies made by `fetch()`/OpenSSL. `Buffer.fill(0)` zeroes the primary copy; exposure window drops from process lifetime to ~50ms per request. Documented limitation. |

## What We Adopt from OpenFang (Design Patterns, Not Code)

| Pattern | Phase | Node.js Implementation |
|---------|-------|----------------------|
| Merkle hash-chain | 1 | `node:crypto` SHA-256, ~25 lines in existing AuditLogger |
| SSRF protection | 1 | `node:dns` + private IP check, ~40 lines |
| GCRA rate limiting | 1 | In-memory TAT map, ~25 lines |
| Loop guard (ping-pong) | 1 | SHA-256 hash history + escalation, ~60 lines |
| Output truncation | 1 | Size cap before response return |
| Constant-time comparison | 1 | `crypto.timingSafeEqual`, 1 line |
| Secret zeroization | 0 | Buffer-based secrets, fill(0) in finally blocks |
| Ed25519 signing | 2 | `node:crypto` Ed25519, ~30 lines |
| Capability inheritance | 2 | Parent grant set check on spawn |
| Context budget | 2 | Character counting, 2-layer caps |
| Recursion depth | 2 | Depth counter on agent spawn |
| Taint tracking | 3 | TypeScript branded types, compile-time only |
| RBAC capability gates | 3 | 4-tier role hierarchy |

---

## LOE Summary

| Phase | Duration | New Code | What You Get |
|-------|----------|----------|-------------|
| **Phase 0** | 3-5 days | ~150 lines + bug fixes | **Working system** — can run an agent safely on Mac Mini |
| **Phase 1** | 2-3 weeks | ~300 lines + tests + claude-mem | **Confident system** — catches real attacks, tamper-evident audit, memory hardened |
| **Phase 2** | 4-6 weeks | ~400 lines + integrations | **Personal AI platform** — Gmail, Calendar, 16 agents, OpenClaw, sqlite-vec, Plano routing |
| **Phase 2.5** | 2 weeks | ~250 lines + hooks | **Unified security** — Claude Code + OpenClaw share same Sentinel pipeline |
| **Phase 3** | 4-6 weeks | ~250 lines | **Data governance** — domain isolation, financial safety, taint tracking |
| **Total** | ~15-21 weeks | ~1,350 lines | Full personal AI platform with production-grade security |

Phase 3 is fully deferrable. Phase 2.5 can run concurrently with Phase 2 (independent work streams). Without Phase 3: **~11-15 weeks** to a working, unified personal AI platform.

---

## Verification

### After Phase 0
1. `pnpm test` — all 231 existing tests pass (no regressions from bug fixes)
2. `docker compose up` — executor starts, agent connects
3. Send `bash: "git status"` manifest → auto-approved, result returned without false-positive redaction
4. Send `bash: "sh -c 'echo $ANTHROPIC_API_KEY'"` → classified as dangerous, confirmation prompt appears
5. Deny the confirmation → agent receives rejection
6. Send `write_file: "/etc/passwd"` from agent with `allowedRoots: ["~/Code"]` → rejected
7. Check audit log → entry exists with all fields populated
8. Check vault decrypt path → API key `Buffer` is zeroed after use
9. **OWASP gate**: Review `/execute`, `/confirm`, `/proxy/llm` for A01/A03/A05 → document in `docs/owasp-reviews/phase-0.md`

### After Phase 1
10. Tamper with an audit row → `verifyChain()` detects break
11. Send LLM proxy request to `http://127.0.0.1:8080` → SSRF rejected
12. Send 25 identical `bash: "ls"` calls in 3 seconds → loop guard triggers
13. Send 50 rapid requests → rate limiter returns 429
14. Tool output containing SSN `123-45-6789` → replaced with `[REDACTED]`
15. All 12 invariant tests pass
16. claude-mem hardened: oversized observation rejected, credential in memory entry blocked
17. Rampart evaluation documented: overlap analysis, adoption recommendation
18. **OWASP gate**: Review SSRF guard, rate limiter, Merkle audit, PII scrubber for A02/A09/A10 → document in `docs/owasp-reviews/phase-1.md`

### After Phase 2
19. Google Workspace tools available via MCP
20. Agent roster: 16 agents configured with sensitivity tiers
21. System prompts (soul.md): each agent has a soul.md following Anthropic's best practices — role, tone, safety boundaries, sensitivity-tier-appropriate constraints
22. OpenClaw skill executes inside `isolated-vm` isolate
23. Ed25519-signed manifests verified before execution
24. OpenClaw sends `delegate.code` manifest → user confirms → Claude Code spawns in worktree → creates PR
25. Heartbeat cron detects dead Claude Code session → restarts it → session completes → PR created
26. Nightly consolidation reviews audit log → updates claude-mem with learnings
27. Claude Code spawned via delegation runs with `--allowedTools` whitelist + `--max-budget-usd` cap
28. sqlite-vec: semantic search returns relevant memories alongside FTS5 keyword results
29. Plano routing: GPT latest handles simple tasks, Claude Opus handles complex reasoning
30. Prompt caching: repeated system prompts hit cache for all 3 providers — verify reduced latency/cost in LLM proxy logs
31. Model Armor evaluation documented: cost, latency, coverage vs. local controls
32. **OWASP gate**: Review MCP tool proxies, delegation flow, Google API surface for A01/A03/A07 → document in `docs/owasp-reviews/phase-2.md`

### After Phase 2.5
33. Claude Code PreToolUse hook → Sentinel classifies `bash: "rm -rf /"` → blocked
34. Claude Code PostToolUse hook → credential in MCP response → stripped before Claude sees it
35. Gmail MCP via Sentinel proxy → PII in email body → scrubbed in audit log
36. Audit log shows both OpenClaw and Claude Code entries with `source` column
37. Sentinel rate limiter applies to Claude Code tool calls (same GCRA as OpenClaw)
38. Claude Code `bash: "curl http://169.254.169.254"` → Sentinel SSRF guard rejects via classify hook
39. **OWASP gate**: Review hook-to-executor path, classify/filter endpoints, MCP proxy auth for A01/A03/A07/A09 → document in `docs/owasp-reviews/phase-2.5.md`
