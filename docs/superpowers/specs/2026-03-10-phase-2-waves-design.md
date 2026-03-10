# Phase 2 Design: Four-Wave Decomposition

**Date**: 2026-03-10
**Status**: Approved (post-review, 13 issues resolved)
**Scope**: Phase 2 of Sentinel roadmap — Integrations + Real Agents

---

## Context

Phase 1 is complete (542 tests, 12 security invariants, Merkle audit, memory store). Phase 2 connects Sentinel to real-world services and agent runtimes. The original Phase 2 was a monolithic 4-6 week block with 17 tasks — too large to execute without clear sequencing.

This design decomposes Phase 2 into four waves with explicit dependencies, ordered by "security floor rises before new attack surfaces open."

### Key Spike Finding: OpenClaw Plugin Architecture

A source code analysis of [openclaw/openclaw](https://github.com/openclaw/openclaw) revealed that the planned MCP proxy integration approach is **not viable** — OpenClaw does not use MCP. Instead, OpenClaw has a comprehensive plugin system (`OpenClawPluginApi`) with 24 hook points including `before_tool_call`, `after_tool_call`, and `tool_result_persist` — exactly what Sentinel needs.

**This changes Wave 2.3 from "build an MCP proxy" to "build a Sentinel OpenClaw plugin."**

Other spike findings:
- LLM proxy redirect is config-only (`models.providers.<id>.baseUrl` in `openclaw.json`)
- OpenClaw already has `SOUL.md` as a first-class concept — soul.md authoring aligns with their system
- Node 22+ required (Sentinel currently targets Node 18+ — alignment needed)
- OpenClaw has its own exec approval system, sandbox Docker, and security module — Sentinel complements rather than replaces
- OpenClaw uses TypeBox for schemas (not Zod) — but plugin hooks are function-based, so schema interop is minimal
- `pi-agent-core` is an external dependency (`@mariozechner/pi-agent-core`) — the core agent loop is in this library

---

## Wave Structure

```
Wave 2.1: Security Primitives          (~2.5 days)
    ↓
Wave 2.2: Google Workspace + Email     (~1.5 weeks)
    ↓
Wave 2.3: OpenClaw + Sentinel          (~3-3.5 weeks)
    ↓
Wave 2.4: LLM Infrastructure           (~4.5 days)
```

Total: ~6-7 weeks. Each wave has an OWASP gate review before proceeding.

### Deferred to Phase 3
- PostHog analytics
- Capability inheritance (child agents can't exceed parent)
- Claude Code integration (Phase 2.5 in roadmap): MCP proxy server, PreToolUse/PostToolUse hook scripts, Claude Code scope config, integration tests for hooks → executor → audit pipeline. These remain in the roadmap at `docs/plans/path-a-v2-adopt-openfang-primitives.md` §Phase 2.5 but are explicitly deferred — the `/classify` and `/filter-output` endpoints built in Wave 2.3 are prerequisites that make Phase 2.5 faster when we get there.

---

## Wave 2.1: Security Primitives (~2.5 days)

**Goal**: Harden the execution pipeline before opening new attack surfaces in Waves 2.2-2.3.

| Task | What It Does | LOE |
|------|-------------|-----|
| Ed25519 manifest signing | Non-repudiation for audit trail forensics. Executor generates Ed25519 keypair at startup, signs manifests, stores signature in audit entry. `verifyChain()` also verifies signatures. | 2 hr |
| Irreversible action classification | New `write-irreversible` category. Send email, calendar invite with attendees, financial transactions = higher confirmation threshold. Confirmation UI shows "This action cannot be undone" warning. | 2 days |

### Ed25519 Signing Design

```
Agent → ActionManifest → Executor
                            ↓
                     Ed25519 sign(manifest_hash)
                            ↓
                     AuditEntry { ..., signature: hex }
                            ↓
                     verifyChain() checks both
                       Merkle hash AND manifest signature
```

**Files**:
- `packages/crypto/src/signing.ts` (new, ~30 LOC) — `generateKeyPair()`, `sign(data)`, `verify(data, sig, pubkey)`
- `packages/types/src/manifest.ts` — add `signature?: string` to `ActionManifest`
- `packages/types/src/audit.ts` — add `signature?: string` to `AuditEntrySchema`
- `packages/audit/src/logger.ts` — store signature, verify in `verifyChain()`
- `packages/executor/src/server.ts` — sign on POST `/execute`

### Irreversible Action Classification Design

The full category-to-decision mapping after Wave 2.1:

| Category | Decision | Auto-approve? | Description |
|----------|----------|---------------|-------------|
| `read` | `auto_approve` | Yes | Read-only operations (file read, gmail.list) |
| `write` | `auto_approve` or `confirm` | Config-dependent | Reversible writes (file write, calendar create without attendees) |
| `write-irreversible` | `confirm` | **Never** | Irreversible actions (email send, calendar invite with attendees) |
| `dangerous` | `confirm` | **Never** | Arbitrary code execution, shell inline-exec, etc. |

`write-irreversible` is a refinement of `write` — it never auto-approves regardless of config. `dangerous` remains for arbitrary code execution patterns. Both route to confirmation, but `write-irreversible` additionally shows the "cannot be undone" warning in the TUI.

```
Tool call received
    ↓
Classifier checks tool + params
    ↓
Is it irreversible?
  - tool=gmail, action=send → YES
  - tool=calendar, action=create_event, has attendees → YES
  - tool=bash, command contains mail/sendmail → YES
    ↓
Category: "write-irreversible" (always confirm, no auto-approve)
    ↓
Confirmation TUI shows warning: "This action cannot be undone"
```

**Files**:
- `packages/types/src/manifest.ts` — add `"write-irreversible"` to `ActionCategory` enum: `z.enum(["read", "write", "write-irreversible", "dangerous"])`
- `packages/policy/src/classifier.ts` — add irreversible detection logic
- `packages/cli/src/confirmation-tui.ts` — add warning display for irreversible actions

### Wave 2.1 Tests (~10 tests)
- Ed25519 sign/verify roundtrip
- Tampered manifest signature detected by `verifyChain()`
- Unsigned manifest accepted (backward compat)
- Email send classified as `write-irreversible`
- Calendar invite with attendees classified as `write-irreversible`
- Calendar event without attendees classified as `write` (not irreversible)
- `write-irreversible` always routes to confirmation (never auto-approve)
- Confirmation UI displays warning text for irreversible actions

---

## Wave 2.2: Google Workspace CLI + Email Defense (~1.5 weeks)

**Goal**: Add real-world service tools and harden the email attack surface.

| Task | What It Does | LOE |
|------|-------------|-----|
| Google Workspace CLI integration | Gmail, Calendar, Drive as executor tool handlers. OAuth2 credentials stored in vault. All calls go through existing guard pipeline. | 1 week |
| Email prompt injection defense | Email bodies treated as untrusted input. Scanner detects hidden text, encoding tricks, instruction override attempts. | 2 days |

### Google Workspace Integration Design

Google Workspace tools are registered as executor tool handlers (same pattern as `bash.ts`, `read-file.ts`). They are NOT MCP servers — they're native Sentinel tools that call Google APIs directly.

```
Agent → ActionManifest { tool: "gmail.send", params: {...} }
    ↓
Executor guard pipeline (classify → rate limit → loop guard → confirm)
    ↓
Gmail tool handler → Google API (OAuth2, credentials from vault)
    ↓
Output filters (credential filter → PII scrub → audit)
    ↓
Sanitized result → Agent
```

**Tool handlers** (new files in `packages/executor/src/tools/`):
- `gmail.ts` — `gmail.list`, `gmail.read`, `gmail.send`, `gmail.search`
- `calendar.ts` — `calendar.list`, `calendar.create`, `calendar.update`, `calendar.delete`
- `drive.ts` — `drive.list`, `drive.read`, `drive.upload`

**Classification**:
- `gmail.list`, `gmail.read`, `gmail.search` → `read` (auto-approve)
- `gmail.send` → `write-irreversible` (always confirm)
- `calendar.list` → `read`
- `calendar.create` with attendees → `write-irreversible`
- `calendar.create` without attendees → `write`
- `drive.list`, `drive.read` → `read`
- `drive.upload` → `write`

**Credential storage**: Google OAuth2 tokens stored in vault alongside API keys. `sentinel init` wizard gets a Google Workspace section.

**Why not MCP**: Sentinel's executor already has a guard pipeline that all tools pass through. Using native tool handlers means Gmail/Calendar/Drive get the full 8-stage pipeline (classify, rate limit, loop guard, confirm, execute, credential filter, PII scrub, audit) automatically. MCP would add an unnecessary indirection layer.

### Email Prompt Injection Defense Design

All email content (subject, body, headers) is treated as untrusted input. A dedicated scanner runs before email content enters the agent's context.

**Detection patterns**:
- Hidden text (white-on-white CSS, zero-width characters, HTML comments with instructions)
- Encoding tricks (base64-encoded instructions, HTML entity obfuscation, Unicode confusables)
- Instruction override attempts ("ignore previous instructions", "system:", role injection)
- SMTP header injection (newline injection in To/CC/BCC fields)

**Scanner placement**: Post-execution filter in `gmail.read` and `gmail.search` handlers. Fires BEFORE output reaches agent context.

```
Gmail API response
    ↓
Email injection scanner (flag suspicious patterns)
    ↓
Standard output filters (credential + PII)
    ↓
Audit log (injection attempts logged with severity)
    ↓
Sanitized result → Agent
```

**Modes** (aligned with content moderation):
- `enforce`: Flagged content replaced with `[SUSPICIOUS_CONTENT_REMOVED]`
- `warn`: Flagged but content passes through, logged to audit
- `off`: No scanning

**Files**:
- `packages/executor/src/moderation/email-scanner.ts` (new, ~80 LOC)
- `packages/executor/src/tools/gmail.ts` — wire scanner in read/search handlers
- `packages/types/src/credential-patterns.ts` — add Google OAuth token patterns (`ya29.*`, refresh tokens) to credential detection

### Wave 2.2 Tests (~50 tests)
- Gmail CRUD operations (list, read, send, search) with mock Google API
- Calendar CRUD with attendee detection
- Drive read/upload
- OAuth2 token refresh flow
- Email injection: hidden text detected
- Email injection: base64 instructions detected
- Email injection: "ignore previous instructions" flagged
- Email injection: SMTP header injection blocked
- Email injection: false negative rate on legitimate emails
- All Google tools go through guard pipeline (rate limit, loop guard, audit)
- Gmail send classified as `write-irreversible`
- Credential filter strips Google OAuth tokens from responses

### Cross-Wave Note
These Google Workspace tools will be consumable by OpenClaw agents in Wave 2.3 — the Sentinel plugin exposes them via `before_tool_call`/`after_tool_call` hooks. The tool handlers themselves don't change.

---

## Wave 2.3: OpenClaw + Sentinel (~3-3.5 weeks)

**Goal**: Wire OpenClaw's agent runtime through Sentinel's security pipeline via the OpenClaw plugin system.

### Spike Findings Summary

OpenClaw (https://github.com/openclaw/openclaw) is a TypeScript monorepo personal AI assistant with:
- WebSocket Gateway control plane (:18789)
- `pi-agent-core` agent runtime with tool streaming
- **24 plugin hook points** including `before_tool_call`, `after_tool_call`, `tool_result_persist`
- `SOUL.md` as a first-class system prompt concept
- Own exec approval system, Docker sandbox, and security module
- NO MCP support — all tools are native or plugin-registered
- LLM provider `baseUrl` configurable per-provider in `openclaw.json`
- Node 22+ required

### Integration Architecture: Sentinel OpenClaw Plugin

**Approach**: Build an OpenClaw plugin that bridges every tool call through Sentinel's executor pipeline. No OpenClaw source modifications required.

```
OpenClaw Gateway (:18789)
    ↓ tool call
Plugin: before_tool_call hook
    ↓ POST /execute (ActionManifest)
Sentinel Executor (:3141)
    ↓ classify → rate limit → loop guard → confirm → execute
    ↓ credential filter → PII scrub → audit
    ↓ result
Plugin: after_tool_call hook
    ↓ tool_result_persist hook (final sanitization)
OpenClaw agent context
```

**LLM calls**: Redirect via `openclaw.json` config:
```json
{
  "models": {
    "providers": {
      "anthropic": {
        "baseUrl": "http://localhost:3141/proxy/llm/anthropic"
      },
      "openai": {
        "baseUrl": "http://localhost:3141/proxy/llm/openai"
      },
      "google": {
        "baseUrl": "http://localhost:3141/proxy/llm/google"
      }
    }
  }
}
```

This routes all LLM calls through Sentinel's proxy for credential injection + SSRF protection. OpenClaw's own API key config is bypassed — Sentinel's vault handles credentials.

### Sentinel Plugin Design

**Location**: `~/.openclaw/extensions/sentinel/` (OpenClaw's plugin directory on the host). Source lives in our repo at `packages/openclaw-plugin/` and is symlinked or copied during `sentinel init`. This keeps the plugin in our pnpm workspace for development/testing while deploying to OpenClaw's expected location.

**Plugin structure**:
```
packages/openclaw-plugin/
├── index.ts           # Plugin entry point, registers hooks
├── manifest-bridge.ts # Translates OpenClaw tool calls → Sentinel ActionManifests
├── executor-client.ts # HTTP client for Sentinel executor (:3141)
├── config.ts          # Plugin config (executor URL, enabled hooks)
└── __tests__/
    └── plugin.test.ts
```

**Hook registrations**:

```typescript
// Pseudocode — actual implementation follows OpenClaw plugin API
export default function sentinelPlugin(api: OpenClawPluginApi) {
  // 1. Intercept all tool calls for classification + audit
  api.on('before_tool_call', async (event) => {
    const manifest = buildManifest(event.toolName, event.params);
    const decision = await executorClient.classify(manifest);

    if (decision === 'block') {
      return { block: true, blockReason: 'Blocked by Sentinel policy' };
    }
    if (decision === 'confirm') {
      // Route to Sentinel confirmation flow
      const confirmed = await executorClient.confirm(manifest);
      if (!confirmed) return { block: true, blockReason: 'User denied' };
    }
    return {}; // allow
  }, { priority: 1 }); // High priority — run first

  // 2. Audit results + scrub credentials/PII
  api.on('after_tool_call', async (event) => {
    await executorClient.audit(event);
  });

  // 3. Final sanitization before transcript write
  api.on('tool_result_persist', (event) => {
    // Synchronous — scrub credentials + PII from message
    return { message: scrubCredentials(scrubPII(event.message)) };
  });

  // 4. Content moderation on LLM input/output
  api.on('llm_input', async (event) => {
    await executorClient.moderate(event.messages, 'pre');
  });
  api.on('llm_output', async (event) => {
    await executorClient.moderate(event.response, 'post');
  });
}
```

**Confirmation flow**: When Sentinel classifies a tool call as `confirm`, the plugin needs to bridge OpenClaw's exec approval system with Sentinel's confirmation TUI. Two options:

1. **Sentinel-only**: Plugin blocks the tool call, posts to Sentinel's `/confirm/:manifestId`, Sentinel's TUI handles it. Simpler, single confirmation UX.
2. **OpenClaw-native**: Plugin returns a modified result that triggers OpenClaw's `ask` mode. More integrated but splits the UX.

**Recommendation**: Option 1 (Sentinel-only) — keeps confirmation UX consistent regardless of agent runtime.

### Task Breakdown

| Task | What It Does | LOE |
|------|-------------|-----|
| OpenClaw setup + install | Install OpenClaw, configure `openclaw.json`, verify Gateway runs alongside Sentinel executor | 1 day |
| Node 22 alignment | Update Sentinel Docker images and CI to Node 22+. Rebuild `better-sqlite3` and `sqlite-vec` native bindings. Test in Docker first. | 4-6 hr |
| Sentinel OpenClaw plugin | `before_tool_call` + `after_tool_call` + `tool_result_persist` hooks → Sentinel executor | 3 days |
| Executor `/classify` endpoint | Accepts tool name + params, returns decision, logs to audit (needed for plugin's `before_tool_call`) | 3 hr |
| Executor `/filter-output` endpoint | Accepts tool output, applies credential + PII filters (needed for plugin's `after_tool_call`) | 2 hr |
| LLM proxy config | Set `baseUrl` per-provider in `openclaw.json` → Sentinel proxy | 1 hr |
| `delegate.code` manifest + CLI handler | OpenClaw proposes coding task → Sentinel confirms → CLI spawns Claude Code in worktree | 3 days |
| Heartbeat scheduled task | Every 5 min: check Claude Code sessions alive, restart dead, notify on PR | 2 days |
| Tool recursion depth limiting | `depth` field on ActionManifest, reject at depth >= 5 | 30 min |
| Context budget enforcement | Per-result 30% cap, global 75% cap in agent context management | 2 hr |
| Soul.md authoring | Write `SOUL.md` for OpenClaw workspace following Anthropic best practices + Sentinel safety boundaries | 2 days |
| Nightly consolidation task | 2 AM cron: review audit log, extract learnings, write to memory store | 1 day |
| Shared audit schema | Add `source: "openclaw" | "claude-code"` column to audit entries. Update `packages/types/src/audit.ts` AuditEntrySchema. | 1 hr |

### Sentinel Plugin ↔ Executor Communication

The plugin runs inside OpenClaw's Gateway process. It communicates with Sentinel's executor over HTTP.

**New executor endpoints** (required for plugin):

`POST /classify` — Classification without execution
```typescript
// Request
{ tool: string, params: Record<string, unknown>, agentId: string, sessionId: string }

// Response
{ decision: "block" | "auto_approve" | "confirm", reason: string, manifestId: string }
```

`POST /filter-output` — Output sanitization without execution
```typescript
// Request
{ output: string, tool: string, agentId: string }

// Response
{ output: string, redacted: boolean, patterns: string[] }
```

These endpoints reuse the existing guard pipeline components (classifier, rate limiter, loop guard, credential filter, PII scrubber) but don't execute tools — they only classify and filter.

Request/response types will be Zod schemas in `packages/types/src/` following the project convention ("Zod for all external input validation").

**Decision mapping for plugin**: Both `auto_approve` and `allow` result in the plugin returning `{}` (proceed). Only `block` and `confirm` trigger plugin action.

### Failure Modes

If Sentinel executor is unreachable (Docker down, network issue), the `before_tool_call` hook will fail. **Default: fail-closed** — all tool calls are blocked when the executor is unreachable. This prioritizes security over availability.

Configuration:
- `failMode: "closed"` (default) — block all tools, log error
- `failMode: "open"` — allow all tools, log warning (for development only)
- `healthCheckInterval: 30000` — periodic health check to executor `/health`
- `connectionTimeout: 5000` — max wait for executor response before treating as unreachable

### delegate.code Flow (Updated)

```
OpenClaw Agent (via Sentinel plugin)
    ↓ before_tool_call: { tool: "delegate.code", params: { task, worktree, budget } }
Sentinel Plugin → POST /classify → decision: "confirm"
    ↓ POST /confirm/:manifestId
Sentinel Confirmation TUI (HOST)
    ↓ user approves
Sentinel CLI → spawns Claude Code:
    claude -p "$(cat task.md)" --worktree feature-xyz \
      --output-format json \
      --allowedTools "Read,Write,Edit,Bash,Glob,Grep" \
      --max-budget-usd 5.0
    env: PRODUCTIVITYHUB_BATCH=1
    ↓
Claude Code (HOST, isolated worktree)
    ↓ creates PR when done
Heartbeat Cron (every 5 min)
    ↓ detects PR → notifies OpenClaw via sessions_send
OpenClaw Agent ← completion signal
```

### SOUL.md Design

OpenClaw loads `~/.openclaw/workspace/SOUL.md` into the system prompt automatically. Our soul.md should define:

1. **Identity**: Sentinel-secured personal AI assistant
2. **Safety boundaries**: Never bypass Sentinel classification, never attempt to access tools outside approved scope
3. **Tone**: Professional, concise, proactive
4. **Sensitivity tiers**: Different behavioral constraints per tier
   - Normal: standard tool access, auto-approve reads
   - High: confirmation required for all writes
   - Critical: confirmation required for all actions, no delegation
5. **Constitutional AI principles**: Refuse harmful requests, flag uncertainty, prefer reversible actions

### Wave 2.3 Tests (~50 tests)
- Sentinel plugin: `before_tool_call` blocks dangerous tools
- Sentinel plugin: `after_tool_call` scrubs credentials from results
- Sentinel plugin: `tool_result_persist` sanitizes transcript
- `/classify` endpoint returns correct decisions
- `/filter-output` endpoint strips credentials + PII
- LLM proxy config routes OpenClaw LLM calls through Sentinel
- `delegate.code` manifest validation (Zod schema)
- `delegate.code` classified as `dangerous`
- Claude Code spawns in worktree with correct args
- Heartbeat detects dead process → restarts
- Heartbeat detects PR → sends notification
- Tool recursion depth: depth >= 5 rejected
- Context budget: per-result 30% cap enforced
- Context budget: global 75% cap enforced
- Nightly consolidation writes observations to memory store
- Audit entries include `source` column
- Shared audit: OpenClaw and Claude Code entries coexist

### Risks
1. **`pi-agent-core` is opaque**: Core agent loop is in an external npm package. Plugin hooks fire around it, not inside it. If the library has bugs or unexpected behavior, we can't patch easily.
2. **Node 22+ migration**: May break `better-sqlite3` native bindings or other Sentinel deps.
3. **Hook execution order**: Other OpenClaw plugins may conflict with Sentinel's `before_tool_call` priority.
4. **Dual confirmation UX**: OpenClaw has its own `ask` mode; Sentinel has its confirmation TUI. Need to disable OpenClaw's `ask` for tools that Sentinel handles.
5. **Gateway must be running**: Sentinel plugin requires OpenClaw Gateway to be running. If Gateway is down, no tool calls are secured.

---

## Wave 2.4: LLM Infrastructure (~4.5 days)

**Goal**: Optimize LLM cost, latency, and evaluation.

| Task | What It Does | LOE |
|------|-------------|-----|
| Plano model routing | Route by task complexity: simple → GPT-4o-mini, medium → Claude Sonnet, complex → Claude Opus. Fallback chains. Cost tracking per agent. | 2 days |
| Prompt caching (all 3 providers) | Anthropic: `cache_control` on system/tool prompts. OpenAI: automatic (no changes). Gemini: `cachedContent`. Track cache hits in audit. | 1 day |
| Promptfoo evals + red teaming | Install Promptfoo, write adversarial test config (jailbreaks, injection, boundary testing), generate report. | 1 day |
| Google Model Armor evaluation | Test free tier, measure latency impact on LLM proxy, compare coverage vs. Sentinel's local controls. Write eval doc. | 4 hr |

### Plano Model Routing Design

Plano sits in Sentinel's LLM proxy (`packages/executor/src/llm-proxy.ts`). When an agent (OpenClaw or Claude Code) makes an LLM call, Plano selects the optimal model.

```
LLM call → Sentinel proxy
    ↓
Plano router:
  1. Check agent's model preference (if set)
  2. Classify task complexity (context length, tool count, task type)
  3. Select model (initial thresholds — tunable via config, validated by Promptfoo evals):
     - Simple (< 4K context, no tools): GPT-4o-mini ($0.15/1M input)
     - Medium (4K-32K, standard tools): Claude Sonnet ($3/1M input)
     - Complex (> 32K, reasoning-heavy): Claude Opus ($15/1M input)
  4. Fallback chain if primary fails:
     Claude Opus → Claude Sonnet → GPT-4o → Gemini Flash
    ↓
Forward to selected provider with correct baseUrl + API key
    ↓
Track: model used, tokens, cost → audit log
```

**Files**:
- `packages/executor/src/plano-router.ts` (new, ~100 LOC) — routing logic
- `packages/executor/src/llm-proxy.ts` — integrate Plano before forwarding
- `packages/types/src/config.ts` — add Plano config to `SentinelConfig`

### Prompt Caching Design

| Provider | Mechanism | Implementation |
|----------|-----------|----------------|
| Anthropic | `cache_control: { type: "ephemeral" }` on system prompt blocks ≥ 1024 tokens | LLM proxy injects `cache_control` on first system message |
| OpenAI | Automatic (prefix matching, 4K chunks) | No changes — automatic |
| Gemini | `cachedContent` API — create cached content, reference by name. Minimum 32K tokens required; content below threshold falls back to no-cache. TTL managed by proxy (default 1 hour, configurable). | LLM proxy creates cache on first call, references on subsequent. Falls back gracefully when content is below 32K threshold. |

**Files**:
- `packages/executor/src/llm-proxy.ts` — inject cache headers per provider
- `packages/executor/src/prompt-cache.ts` (new, ~50 LOC) — Gemini cache management

### Cross-Wave Note: Plano + OpenClaw

OpenClaw has its own model failover system (`fallbacks` array per agent). With Sentinel's LLM proxy, there are two options:
1. **Sentinel-only routing**: Disable OpenClaw's failover, let Plano handle all routing
2. **Layered routing**: OpenClaw selects preferred model, Plano handles failover within that preference

**Recommendation**: Option 1 — centralize routing in Plano for consistent cost tracking and audit.

### Wave 2.4 Tests (~25 tests)
- Plano: simple task routes to GPT-4o-mini
- Plano: complex task routes to Claude Opus
- Plano: fallback chain triggers on provider failure
- Plano: cost tracked per agent in audit
- Prompt cache: Anthropic `cache_control` header injected
- Prompt cache: Gemini cached content created and referenced
- Promptfoo: adversarial config validates against jailbreaks
- Promptfoo: injection attempts in tool params detected

---

## Phase Gates

Each wave ends with verification before proceeding:

| Gate | Scope | OWASP Focus |
|------|-------|-------------|
| Post-2.1 | Ed25519 signing, irreversible classification | A02 (crypto), A01 (access control) |
| Post-2.2 | Google Workspace tools, email injection | A03 (injection), A07 (auth) |
| Post-2.3 | OpenClaw plugin, delegation flow, shared audit | A01 (access control), A09 (logging), A03 (injection via agent) |
| Post-2.4 | LLM routing, prompt caching, red teaming | A10 (SSRF via model endpoints), A03 (prompt injection) |

---

## Success Criteria

### Wave 2.1 Complete When:
- [ ] Ed25519 signatures stored in audit entries
- [ ] `verifyChain()` detects tampered signatures
- [ ] `gmail.send` classified as `write-irreversible`
- [ ] Confirmation TUI shows irreversibility warning
- [ ] ~10 new tests passing

### Wave 2.2 Complete When:
- [ ] Gmail, Calendar, Drive tools functional via executor
- [ ] All Google tools go through full guard pipeline
- [ ] Email injection scanner detects hidden text + encoding tricks
- [ ] OAuth2 credentials stored in vault (not env vars)
- [ ] ~50 new tests passing

### Wave 2.3 Complete When:
- [ ] OpenClaw Gateway runs alongside Sentinel executor
- [ ] Sentinel plugin intercepts all OpenClaw tool calls
- [ ] LLM calls route through Sentinel proxy (config-only)
- [ ] `delegate.code` → user confirms → Claude Code spawns in worktree → PR created
- [ ] Heartbeat detects dead sessions and restarts them
- [ ] Nightly consolidation writes learnings to memory store
- [ ] Audit log shows both OpenClaw and Claude Code entries
- [ ] SOUL.md authored with Sentinel safety boundaries
- [ ] ~50 new tests passing

### Wave 2.4 Complete When:
- [ ] Plano routes simple/medium/complex tasks to appropriate models
- [ ] Prompt caching active for Anthropic and Gemini
- [ ] Promptfoo adversarial report generated
- [ ] Google Model Armor evaluation documented
- [ ] ~25 new tests passing

### Phase 2 Total:
- ~135 new tests (677+ total)
- ~1,200 new LOC (excluding soul.md and config)
- All 4 OWASP gate reviews documented

---

## Appendix A: OpenClaw Plugin Hook Reference

The 24 hooks available in `OpenClawPluginApi.on()`:

| Hook | Phase | Sentinel Use |
|------|-------|-------------|
| `before_tool_call` | Pre-exec | **Primary**: classify, rate limit, loop guard, block/confirm |
| `after_tool_call` | Post-exec | **Primary**: audit results, duration tracking |
| `tool_result_persist` | Post-exec (sync) | **Primary**: credential + PII scrubbing before transcript |
| `llm_input` | Pre-LLM | Content moderation (pre-execute scan) |
| `llm_output` | Post-LLM | Content moderation (post-execute scan) |
| `before_agent_start` | Agent lifecycle | Log agent spawn, check capability inheritance |
| `agent_end` | Agent lifecycle | Log agent completion |
| `subagent_spawning` | Agent lifecycle | Enforce recursion depth limit |
| `subagent_spawned` | Agent lifecycle | Track active agent count |
| `subagent_ended` | Agent lifecycle | Cleanup tracking |
| `session_start` | Session lifecycle | Initialize per-session rate limiter |
| `session_end` | Session lifecycle | Session summary → memory consolidation |
| `gateway_start` | Gateway lifecycle | Verify Sentinel executor reachable |
| `gateway_stop` | Gateway lifecycle | Flush audit buffer |
| Others (10) | Various | Not used by Sentinel initially |

### `before_tool_call` Hook Signature

```typescript
type PluginHookBeforeToolCallEvent = {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
};

type PluginHookBeforeToolCallResult = {
  params?: Record<string, unknown>;  // modify params
  block?: boolean;                    // block execution
  blockReason?: string;               // reason for blocking
};
```

### `after_tool_call` Hook Signature

```typescript
type PluginHookAfterToolCallEvent = {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
  result?: unknown;
  error?: string;
  durationMs?: number;
};
```

---

## Appendix B: Spike — Full OpenClaw Analysis

### Architecture
- TypeScript monorepo (pnpm workspaces)
- Gateway: WebSocket control plane at `ws://127.0.0.1:18789`
- Agent: `pi-agent-core` runtime (external npm package by @mariozechner)
- Config: `~/.openclaw/openclaw.json`
- Workspace: `~/.openclaw/workspace/` (SOUL.md, AGENTS.md, TOOLS.md, skills/)
- Node 22+ required

### Tool Dispatch Pipeline
1. LLM response → `pi-agent-core` framework parses tool calls
2. `attempt.ts` assembles tools via `createOpenClawCodingTools()` + `splitSdkTools()`
3. Framework calls `tool.execute(toolCallId, args, signal, onUpdate)`
4. Plugin hooks fire: `before_tool_call` → execution → `after_tool_call` → `tool_result_persist`
5. Results added to message history via `activeSession.agent.replaceMessages()`

### Security Infrastructure (Existing)
- Exec approval system: `security` modes (deny/allowlist/full), `ask` modes (off/on-miss/always)
- Docker sandbox: per-session containers with `readOnlyRoot`, `capDrop`, seccomp, AppArmor
- Path sandboxing: `assertSandboxPath()` prevents traversal + symlink escapes
- Obfuscation detection: `exec-obfuscation-detect.ts`
- Skill scanner: `skill-scanner.ts` scans for dangerous patterns
- Audit logging: `security/audit.ts`
- Constant-time comparison: `security/secret-equal.ts`

### No MCP
Zero MCP files in the repository. All tools are native (built-in) or plugin-registered.

### SOUL.md
- Loaded as `EmbeddedContextFile` into system prompt's "Project Context" section
- When present: "If SOUL.md is present, embody its persona and tone"
- Three prompt modes: `full` (main agents), `minimal` (subagents), `none` (basic identity)

### Model Configuration
```typescript
type ModelProviderConfig = {
  baseUrl?: string;     // ← redirect to Sentinel proxy
  apiKey?: string;
  auth?: "api-key" | "oauth" | "aws-sdk" | "token";
  api?: "openai-completions" | "anthropic-messages" | "google-generative-ai" | ...;
};
```

### Risks Identified
1. `pi-agent-core` is opaque — tool dispatch internals are in external package
2. Node 22+ may break Sentinel's `better-sqlite3` native bindings
3. ACP runtime is a second execution path (separate from pi-agent-core)
4. `before_tool_call` can block but cannot redirect execution
5. Plugin API stability unknown — no semver guarantees on hook signatures
6. OpenClaw actively developed (v2026.3.9) — may diverge
