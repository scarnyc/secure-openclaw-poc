# Sentinel Pipeline State Machine — Phase 2

> **Snapshot**: Post-Wave 2.2c (847 tests, 9 packages) — Ed25519 manifest signing, `write-irreversible` classification, GWS CLI integration, credential zeroization (`useCredential()`), HMAC response signing, body size limits, ReDoS-hardened classifier, dual audit entries (pending + final).
>
> **Master plan**: [`docs/plans/path-a-v2-adopt-openfang-primitives.md`](plans/path-a-v2-adopt-openfang-primitives.md)
>
> **Previous**: [`docs/pipeline-state-machine-phase-1.5.md`](pipeline-state-machine-phase-1.5.md) — Phase 1.5 pipeline (542 tests, 8 packages).

```
              ┌──────────────────────────────────────────────────────┐
              │                 HOST BOUNDARY                        │
              │         Rampart Firewall (launchd daemon)            │
              │    45 standard + 3 Sentinel project policies         │
              │                                                      │
              │  PreToolUse hook on ALL Claude Code tool calls:      │
              │  ┌────────────────────────────────────────────────┐  │
              │  │  Bash, Read, Write, Edit, Glob, Grep, ...     │  │
              │  │                                                │  │
              │  │  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │  │
              │  │  │ DENY     │  │ ASK      │  │ ALLOW       │  │  │
              │  │  │ vault.enc│  │ security │  │ source code │  │  │
              │  │  │ audit.db │  │ code     │  │ tests       │  │  │
              │  │  │ memory.db│  │ edits    │  │ docs        │  │  │
              │  │  │ *.tfstate│  │          │  │ config      │  │  │
              │  │  │ SSH keys │  │          │  │             │  │  │
              │  │  └──────────┘  └──────────┘  └─────────────┘  │  │
              │  └────────────────────────────────────────────────┘  │
              └──────────────────────┬──────────────────────────────┘
                                    │ tool call allowed
                          ┌─────────▼────────┐
                          │   USER INPUT     │
                          │  (terminal/TUI)  │
                          └────────┬─────────┘
                                   │
                          ┌────────▼─────────┐
                          │  AGENT PROCESS   │
                          │  (untrusted)     │
                          │                  │
                          │ ┌──────────────┐ │
                          │ │ Add to       │ │
                          │ │ Conversation │ │
                          │ │ Context      │ │
                          │ └──────┬───────┘ │
                          │        │         │
                          │ ┌──────▼───────┐ │
                          │ │ Call LLM     │ │◄─────────────────────────┐
                          │ │ (via proxy)  │ │                         │
                          │ └──────┬───────┘ │                         │
                          │        │         │                         │
                          │   ┌────▼────┐    │                         │
                          │   │ Text?   │    │                         │
                          │   └─┬────┬──┘    │                         │
                          │  yes│    │no     │                         │
                          │     │ ┌──▼─────┐ │                         │
                          │  display│Tool  │ │                         │
                          │  to  │ call?  │ │                         │
                          │  user└──┬─────┘ │                         │
                          │        yes      │                         │
                          │   ┌────▼──────┐ │    ┌──────────────────┐  │
                          │   │ Build     │ │    │ Add ToolResult   │  │
                          │   │ Action    ├─┼───►│ to context,      ├──┘
                          │   │ Manifest  │ │    │ loop again       │
                          │   └───────────┘ │    └──────────────────┘
                          └────────┼────────┘
                                   │ POST /execute
                    ═══════════════╪══════════════════
                     TRUST BOUNDARY (HTTP :3141)
                    ═══════════════╪══════════════════
                                   │
                          ┌────────▼─────────┐
                          │ EXECUTOR PROCESS │
                          │ (trusted)        │
                          └────────┬─────────┘
                                   │
    ┌──────────────────────────────▼──────────────────────────────────┐
    │                     HTTP MIDDLEWARE (NEW)                        │
    │                     (applied before route handlers)             │
    │                                                                 │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
    │  │ 1.Request│  │ 2.Body   │  │ 3.HMAC   │  │ 4.Auth       │   │
    │  │ ID       │→│ Size     │→│ Response │→│ Middleware    │   │
    │  │ (UUID v4)│  │ Limits   │  │ Signer   │  │ (SHA-256     │   │
    │  │          │  │ (10/25MB)│  │ (SHA-256)│  │  const-time) │   │
    │  │          │  │ →413     │  │          │  │ →401         │   │
    │  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
    │                                                                 │
    └──────────────────────────────┬──────────────────────────────────┘
                                   │
    ┌──────────────────────────────▼──────────────────────────────────┐
    │                     GUARD PIPELINE                              │
    │                     (fail-fast, sequential)                     │
    │                                                                 │
    │  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌──────────────┐  │
    │  │ 5.Validate│→│ 6.Rate    │→│ 7.Loop   │→│ 8.Policy     │  │
    │  │ Manifest │  │ Limiter   │  │ Guard    │  │ Classify     │  │
    │  │ (Zod)    │  │ (GCRA     │  │ (SHA-256 │  │ (bash parse  │  │
    │  │          │  │  per-agent)│  │  fingerp)│  │  + GWS +     │  │
    │  │ →400     │  │ →422+audit│  │ →422+aud │  │  config +    │  │
    │  │          │  │           │  │          │  │  ReDoS)      │  │
    │  └──────────┘  └───────────┘  └──────────┘  └──────┬───────┘  │
    │                                                     │          │
    │                                            ┌────────▼────────┐ │
    │                                            │ DECISION        │ │
    │                                            │ ROUTING         │ │
    │                                            └──┬──────┬────┬──┘ │
    │                                    ┌──────────┘      │    └──────────┐
    │                                    │                 │               │
    │                               ┌────▼───┐    ┌───────▼──────┐  ┌─────▼──────────┐
    │                               │ BLOCK  │    │ AUTO_APPROVE │  │ CONFIRM        │
    │                               │→error  │    │ (read ops)   │  │ (write/        │
    │                               │+audit  │    │              │  │  write-irrevers│
    │                               └────────┘    └───────┬──────┘  │  /dangerous)   │
    │                                                     │         └─────┬──────────┘
    │                                                     │               │
    │                                                     │    ┌──────────▼──────────┐
    │                                                     │    │ AWAITING            │
    │                                                     │    │ CONFIRMATION        │
    │                                                     │    │ (5-min timeout)     │
    │                                                     │    └───┬────────┬────┬───┘
    │                                                     │       │        │    │
    │                                                     │ ┌─────▼──┐ ┌──▼───┐│
    │                                                     │ │APPROVED│ │DENIED││
    │                                                     │ └─────┬──┘ │→error││
    │                                                     │       │    │+audit││
    │                                                     │       │    └──────┘│
    │                                                     │       │    ┌──▼────┘
    │                                                     │       │    │TIMEOUT
    │                                                     │       │    │→auto-deny
    │                                                     │       │    │+audit
    │                                                     │       │    └───────┘
    │                                                     ├───────┘
    │                                                     │
    │  ┌──────────┐  ┌───────────┐  ┌────────────────────▼──┐  ┌──────────┐   │
    │  │ 9.Pre-   │  │10.Audit:  │  │ 11.TOOL EXECUTE       │  │12.Cred   │   │
    │  │execute   │→│ Pending   │→│ (bash/gws/read/write/ │→│ Filter   │   │
    │  │moderation│  │ (Merkle + │  │  MCP)                 │  │          │   │
    │  │          │  │  Ed25519) │  │                       │  │          │   │
    │  └──────────┘  └───────────┘  └───────────────────────┘  └────┬─────┘   │
    │                                                                │         │
    │  ┌──────────────────────────────────────────────────────────┐  │         │
    │  │ 15. AUDIT LOG (Merkle + Ed25519, pending + final)       │  │         │
    │  └────┬────────────────────────────────────────────────────┘  │         │
    │       │  ┌──────────┐  ┌──────────┐                           │         │
    │       │  │14.Post-  │←│13.PII    │◄──────────────────────────┘         │
    │       │  │execute   │  │ Scrub    │                                     │
    │       │  │moderation│  │          │                                     │
    │       │  └────┬─────┘  └──────────┘                                     │
    │       │       │                                                         │
    └───────┼───────┼─────────────────────────────────────────────────────────┘
            │       │
            ├───────┘
            │
    ┌───────▼────────┐
    │ RETURN         │
    │ ToolResult     │──────────► back to Agent (loop continues)
    └────────────────┘


    ═══════════════════════════════════════════════════════════════
     PARALLEL SUBSYSTEM: MEMORY STORE (@sentinel/memory)
    ═══════════════════════════════════════════════════════════════

    Agent observe() / search() calls flow through the memory pipeline:

    ┌─────────────┐     ┌───────────┐     ┌────────────┐     ┌──────────┐
    │ Validate    │────►│ Scrub     │────►│ Dedup      │────►│ Quota    │
    │ (Zod schema)│     │ Creds+PII │     │ (SHA-256   │     │ (100MB   │
    │             │     │ from types│     │  30s window│     │  global) │
    │ →reject     │     │           │     │  →existing │     │ →reject  │
    └─────────────┘     │ →reject   │     │   ID)      │     └────┬─────┘
                        │  if only  │     └────────────┘          │
                        │  redacted │                       ┌─────▼──────┐
                        └───────────┘                       │ SQLite     │
                                                            │ INSERT     │
                              ┌──────────────────────┐      │ (WAL mode) │
                              │ Embed (optional)     │      └─────┬──────┘
                              │ bge-small-en-v1.5    │            │
                              │ 384-dim, local       │      ┌─────▼──────┐
                              │ →observations_vec    │◄─────┤ FTS5 index │
                              └──────────────────────┘      │ (Porter    │
                                                            │  stemming) │
                                                            └────────────┘

    Search: FTS5 keyword + sqlite-vec KNN → Reciprocal Rank Fusion → top N

    ┌───────────┐     ┌───────────┐     ┌──────────┐     ┌───────────┐
    │ Session   │────►│ Daily     │────►│ Prune    │────►│ Context   │
    │ Summary   │     │ Consolidate    │ (retain  │     │ Builder   │
    │ (per-     │     │ (merge+  │     │  only if │     │ (→system  │
    │  session) │     │  dedup)  │     │  in summ)│     │  prompt)  │
    └───────────┘     └───────────┘     └──────────┘     └───────────┘
```

---

## Three-Layer Security Model

The current architecture enforces security at three independent layers. Each layer operates without knowledge of the others — a compromise at one layer is contained by the remaining two.

```
┌──────────────────────────────────────────────────────────────────────┐
│ LAYER 1: RAMPART (Host Boundary)                                     │
│ What: YAML policy engine, launchd daemon, PreToolUse hook            │
│ Where: Intercepts ALL Claude Code tool calls BEFORE Docker           │
│ Scope: Host-wide — applies to Claude Code, OpenClaw, Cline, etc.    │
│ Audit: Separate hash-chained log (independent of Sentinel)           │
├──────────────────────────────────────────────────────────────────────┤
│ LAYER 2: SENTINEL EXECUTOR (Application Boundary)                    │
│ What: HTTP middleware + guard pipeline + policy classifier            │
│       Body size limits, HMAC signing, ReDoS-hardened classifier      │
│       5-min confirmation timeout, write-irreversible category        │
│ Where: HTTP :3141 inside Docker — agent → executor trust boundary    │
│ Scope: Per-agent, per-session — session-scoped isolation             │
│ Audit: Merkle-chained + Ed25519 signed SQLite append-only log        │
├──────────────────────────────────────────────────────────────────────┤
│ LAYER 3: SENTINEL OUTPUT FILTERS (Data Boundary)                     │
│ What: Credential filter (21 patterns, 3-pass encoding-aware),        │
│       PII scrubber (9 patterns), content moderation,                 │
│       SSE credential filter, email injection scanner                 │
│ Where: Post-execution, before ToolResult returns to agent            │
│ Scope: Per-response — every tool output sanitized                    │
│ Audit: Part of Merkle audit log entry                                │
└──────────────────────────────────────────────────────────────────────┘
```

### What Rampart Provides On Top of Sentinel

Sentinel's executor guards operate **inside Docker** — they protect against a compromised or misbehaving agent process. Rampart operates **outside Docker at the host boundary** and addresses a different threat surface:

| Capability | Sentinel (App Layer) | Rampart (Host Layer) | Why Both Matter |
|------------|---------------------|---------------------|-----------------|
| **Scope** | Agent → executor HTTP boundary | ALL tool calls (Bash, Read, Write, Edit, Glob, Grep) | Rampart catches threats that never reach the executor |
| **Data file protection** | Path whitelist per-agent (`allowedRoots`) | Deny rules for `vault.enc`, `audit.db`, `memory.db`, `*.tfstate` | Rampart blocks direct file reads that bypass executor |
| **Security code gating** | N/A (executor doesn't gate its own source edits) | `ask` on 19 security-critical paths (crypto, policy, audit, guards, validator) | Prevents agent from weakening its own sandbox |
| **Self-modification** | N/A | Blocks `rampart allow`, `rampart setup`, `.rampart/` writes | Policy changes are human-only |
| **Credential files** | Credential filter regex on output | Deny on `.ssh/id_rsa`, `.env`, AWS/GCP creds, macOS Keychain | Rampart prevents the read; Sentinel scrubs if read succeeds |
| **Destructive commands** | Bash deny-list in executor tool handler | Deny on `rm -rf /`, `fdisk`, fork bombs, `halt`, `poweroff` | Rampart blocks before shell spawns; Sentinel blocks at tool handler |
| **Env injection** | N/A | Deny on `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV` | Host-level process hijack prevention Sentinel can't detect |
| **Evasion** | N/A | Blocks backslash tricks (`\rm -rf /`), multi-agent bypass | Rampart's pattern engine catches shell-level evasions |
| **Hot-reload** | Requires restart (frozen config) | Edit `.rampart/policy.yaml` → instant enforcement | Operators can tighten policy without redeploying executor |
| **Multi-agent** | Per-agent via `agentId` in executor | Same policies for Claude Code, OpenClaw, Cline, etc. | Host-wide consistency across all AI tool callers |
| **Response scanning** | Credential filter + PII scrubber in executor | Response scanning (deny known patterns) | Redundant defense-in-depth for credential leakage |
| **Response integrity** | HMAC-SHA256 signing on all responses | N/A | Agent can verify response hasn't been tampered with between containers |
| **Request size limits** | Body size limits per-route (10/25MB) | N/A | Prevents memory exhaustion from oversized payloads |
| **GWS scoping** | Per-agent service allow/deny lists | N/A | Limits which Google Workspace services each agent can access |
| **Email defense** | Email injection scanner + pre-send credential gate | N/A | Prevents credential exfiltration via email body/subject |
| **Streaming defense** | SSE credential filter on LLM proxy | N/A | Scrubs credentials from streaming LLM responses in real-time |

**Key insight**: Rampart is the only layer that can prevent a tool call from ever executing. Sentinel's executor sees the request *after* the shell/filesystem operation is already permitted by the host. Rampart denies at the intent level — before bytes hit disk or network.

---

## Pipeline Phase Breakdown

### Phase 0: Rampart Host Firewall (New)

Before any tool call reaches Docker or the executor, the Rampart daemon (`/opt/homebrew/bin/rampart`) intercepts it via the Claude Code PreToolUse hook. The daemon evaluates the call against two policy layers:

1. **Standard policies** (45 rules) — SSH keys, AWS/GCP/Azure creds, env injection (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`), destructive commands (`rm -rf /`, fork bombs), macOS Keychain, browser data, exfiltration domains, backslash evasion, and self-modification protection.

2. **Sentinel project policies** (`.rampart/policy.yaml`, 3 rules):
   - `sentinel-block-tfstate` — denies read/exec on `*.tfstate` files
   - `sentinel-protect-data` — denies read/exec on `vault.enc`, `audit.db*`, `memory.db*`
   - `sentinel-protect-security-code` — requires user confirmation (`ask`) before write/edit on 19 security-critical source paths

Rampart returns `deny` (tool call blocked), `ask` (user must confirm in terminal), or `allow` (proceed). Denied calls never reach the executor. Rampart maintains its own hash-chained audit log independent of Sentinel's Merkle chain.

### Phase 1: User Input → Agent Context

The CLI (`packages/cli/src/commands/chat.ts`) orchestrates startup: unlocks the encrypted vault, starts the executor on `:3141`, spawns a confirmation poller (long-polls every 500ms), and launches the agent loop. User messages are added to `ConversationContext`, which auto-trims at ~100k tokens to stay within LLM limits.

If the memory store is configured, `buildSessionContext()` injects a "Yesterday's work" section into the system prompt with next steps from the most recent daily summary (~200 tokens budget).

### Phase 2: LLM Call (via Proxy) — UPDATED

The agent has **no internet access** (Docker `internal: true`). All LLM calls route through the executor's `/proxy/llm/*` endpoint, which:
- Validates the target host against an allowlist (Anthropic, OpenAI, Google)
- Runs the **SSRF guard** to block private IPs and cloud metadata endpoints
- Injects API keys from the encrypted vault via the `useCredential()` callback pattern (`packages/crypto/src/use-credential.ts`), not raw env vars. The Buffer is zeroed in `finally`; credential strings become GC-eligible after the callback returns.
- Runs the **SSE credential filter** (`packages/executor/src/sse-credential-filter.ts`) on streaming LLM responses, scrubbing credentials from Server-Sent Events in real-time before they reach the agent.

The LLM proxy handler is created via a factory pattern: `createLlmProxyHandler(vault?, auditLogger?)` — this avoids global state and enables test mocking with dependency injection.

The LLM proxy is a key security primitive — it means the agent process literally cannot exfiltrate data to arbitrary URLs. Even if the LLM is prompt-injected into trying to call a malicious endpoint, the proxy's host allowlist blocks it.

### Phase 3: Action Manifest Construction

When the LLM decides to use a tool, the agent builds an **ActionManifest** — a typed JSON envelope with UUID, timestamp, tool name, parameters, sessionId, and agentId. This is the only way the agent can request side effects.

### Phase 4: HTTP Middleware (NEW)

Before the guard pipeline evaluates the action manifest, four HTTP middleware layers process every inbound request to the executor. These run sequentially on all routes (not just `/execute`):

1. **Request ID** (`packages/executor/src/request-id.ts`) — Assigns a UUID v4 to every inbound request and stores it in the Hono context. The ID is returned as the `X-Request-ID` response header, enabling end-to-end request tracing across audit log entries, error responses, and debug logs.

2. **Body Size Limits** (`packages/executor/src/server.ts`) — Two-layer defense against oversized payloads. First, the `Content-Length` header is checked for fast rejection without reading the body. Second, the actual body bytes are verified to catch chunked transfer encoding bypass attempts that omit `Content-Length`. Limits are route-specific: 10MB for `/execute`, 25MB for `/proxy/llm/*`. Oversized requests receive `413 Payload Too Large`. This middleware is gated behind `SENTINEL_DOCKER=true` to avoid breaking the Hono test client, which doesn't always set `Content-Length`.

3. **HMAC Response Signer** (`packages/executor/src/response-signer.ts`) — Computes HMAC-SHA256 over the response body and sets the `X-Sentinel-Signature` header. This enables the agent to verify that responses haven't been tampered with in transit between containers (e.g., by a compromised network proxy). SSE (streaming) responses receive a `"streaming"` marker since their body is generated incrementally and cannot be pre-signed.

4. **Auth Middleware** (`packages/executor/src/auth-middleware.ts`) — Authenticates requests using constant-time SHA-256 hash comparison of Bearer tokens. The `/health` endpoint is exempted for container orchestration probes. When running in Docker (`SENTINEL_DOCKER=true`) with no auth token configured, requests are rejected with `401 Unauthorized` — this is a fail-safe default that prevents accidentally running an unauthenticated executor in production.

### Phase 5: Guard Pipeline (Steps 5-8) — UPDATED

The executor runs four sequential guards, failing fast on any block:

| Step | Guard | What it does |
|------|-------|-------------|
| 5 | **Manifest Validation** | Zod schema parse — rejects malformed requests (400) |
| 6 | **Rate Limiter** | GCRA algorithm, 60 req/min per agentId — prevents runaway agents |
| 7 | **Loop Guard** | SHA-256 fingerprints `(tool, params)` pairs — warn at 3, block at 5 in 60s window |
| 8 | **Policy Classifier** | Categorizes as `read`/`write`/`write-irreversible`/`dangerous` via bash command parsing, GWS tool classification (`classifyGwsTool()`), and config lookup. ReDoS-hardened: regex patterns capped at 200 chars, nested quantifier detection returns `true` (fail-safe restrictive). |

### Phase 6: Decision Routing — UPDATED

The policy classification maps to one of three actions:
- **`block`** → immediate rejection + audit entry (e.g., `rm -rf /`)
- **`auto_approve`** → skip confirmation, proceed to execution (read-only ops when configured)
- **`confirm`** → enter the human-in-the-loop confirmation state

New in Phase 2:
- Fourth action category: `write-irreversible` maps to `confirm` with additional TUI warning "⚠ CANNOT BE UNDONE" (targets email send, calendar invites with attendees, financial transactions)
- 5-minute confirmation timeout: auto-deny after 300s to prevent resource exhaustion from hung confirmations (pen test finding). Timeout path is same as DENIED — audit entry + error response.

### Phase 7: Pre-Execute Content Moderation

If `SENTINEL_MODERATION_MODE=enforce`, the scanner (`packages/executor/src/moderation/scanner.ts`) checks serialized parameters for prompt injection and data exfiltration patterns **before** the tool runs. In `warn` mode it logs but doesn't block. Scanner covers 11 regex rules: prompt injection (ignore instructions, DAN mode, jailbreak) and data exfiltration (base64 secrets, curl/wget with credentials).

### Phase 8: Tool Execution — UPDATED

The executor runs the tool handler:
- **`bash`** — shell execution with deny-list checks, optional firejail sandboxing (Linux), output truncated at 50KB
- **`read_file`** — path allowlist + `O_NOFOLLOW` symlink protection
- **`write_file`** — path allowlist + `O_NOFOLLOW` + TOCTOU mitigation (inode verification)
- **`edit_file`** — path allowlist + substring replacement
- **`gws`** (`packages/executor/src/tools/gws.ts`) — Google Workspace operations. OAuth token injected from vault via `useCredential()`, set as `GOOGLE_WORKSPACE_CLI_TOKEN` env var. Per-agent scoping: `GwsAgentScopes` with `denyServices` checked before `allowedServices` (deny-first). Email injection scanning (`packages/executor/src/moderation/email-scanner.ts`) on outbound email content. Pre-send credential gating: `containsCredential()` check before subprocess spawn. Supply chain integrity verification (`packages/executor/src/tools/gws-integrity.ts`).
- **MCP tools** — forwarded to registered MCP servers

New in Phase 2: dual audit entry pattern — a "pending" entry is written BEFORE tool execution (step 10), and a "final" entry AFTER all post-processing (step 15). This ensures that even if the tool handler crashes or hangs, the audit log records the attempt.

### Phase 9: Output Sanitization (Steps 12-14) — UPDATED

Three filters clean the tool output before it reaches the agent:

| Step | Filter | Protects against |
|------|--------|-----------------|
| 12 | **Credential Filter** | 21 credential patterns (source: `packages/types/src/credential-patterns.ts`): API keys (Anthropic, OpenAI, Gemini, GitHub, Slack, AWS), Bearer tokens, DB connection strings, PEM private keys, JWT tokens, Stripe keys → `[REDACTED]`. Three-pass encoding-aware approach (`redactAllCredentialsWithEncoding()`): plaintext → base64 decode → URL decode. Recursive depth limit (4 levels, 64KB input cap). |
| 13 | **PII Scrubber** | 9 PII patterns: SSN, phone (3 formats), email, salary (2 formats), LinkedIn URLs, GitHub profile URLs → `[PII_REDACTED]` |
| 14 | **Post-execute Moderation** | Prompt injection in tool output (same scanner as pre-execute) |

All patterns come from a single source of truth in `packages/types/src/credential-patterns.ts`.

### Phase 10: Audit Logging (Merkle Chain + Ed25519) — UPDATED

Every request — regardless of outcome — gets TWO append-only SQLite records:

1. **Pending entry** (step 10, before execution): records that the tool execution was attempted. Contains `manifestId`, `sessionId`, `agentId`, `tool`, `category`, `decision`, `result: "pending"`. This is a pen test H1 finding — ensures crashes or hangs are still audited.

2. **Final entry** (step 15, after post-processing): records the outcome. Contains `result` (success/failure/denied/blocked), `duration_ms`, sanitized output summary.

Both entries are:
- **Merkle-chained**: `entry_hash` = SHA-256 of `[prev_hash, id, timestamp, tool, agentId, result]`, creating a tamper-evident log
- **Ed25519 signed**: signature stored in audit entry, excluded from Merkle hash (signs the hash). Ed25519 signing is now mandatory — `AuditLogger` auto-generates keypair in constructor (`loadOrGenerateSigningKey()`). Signing key stored as `audit-signing.key` (0o600) alongside audit DB.
- `verifyChain(publicKey?)` validates both hash chain AND signatures when public key provided.

### Phase 11: Return to Agent

The `ToolResult` (sanitized output, success flag, duration) returns to the agent over HTTP with `X-Sentinel-Signature` (HMAC) and `X-Request-ID` headers. The agent adds it to the conversation context and loops back to the LLM for the next reasoning step.

---

## Memory Store Subsystem (`@sentinel/memory`)

The memory store operates as a **parallel subsystem** — it does not sit in the main execution pipeline but is called by the agent to persist and retrieve observations across sessions.

### Memory Entry Lifecycle

```
┌────────────────────────────────────────────────────────────┐
│ WRITE PATH: observe() / observeWithEmbedding()             │
│                                                            │
│  Input ──► Zod validate ──► Credential scrub ──► PII scrub │
│                                    │                       │
│                              content-only                  │
│                              sensitive? ──► REJECT          │
│                                    │                       │
│                              SHA-256 hash                  │
│                                    │                       │
│                              dedup check ◄── 30s window    │
│                              (same hash?) ──► return       │
│                                    │         existing ID   │
│                              quota check ◄── 100MB global  │
│                              (over?) ──► REJECT             │
│                                    │                       │
│                              INSERT observations           │
│                              INSERT observations_fts       │
│                                    │                       │
│                              [if embedder configured]      │
│                              embed(title + content)        │
│                              INSERT observations_vec       │
│                                    │                       │
│                              UPDATE storage_stats          │
│                              return UUID                   │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ READ PATH: search() / hybridSearch()                       │
│                                                            │
│  Query ──► parse filters (project, agent, type, dates)     │
│                    │                                       │
│         ┌──────────┴──────────┐                            │
│         │                     │                            │
│    FTS5 keyword          Vector KNN                        │
│    (Porter stemming)     (embed query →                    │
│    title + content +      384-dim cosine                   │
│    concepts               similarity)                      │
│         │                     │                            │
│         └──────────┬──────────┘                            │
│                    │                                       │
│         Reciprocal Rank Fusion                             │
│         score = 1/(K + rank + 1), K=60                     │
│         merge by document ID                               │
│                    │                                       │
│         top N results (limit + offset)                     │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ CONSOLIDATION PATH (periodic)                              │
│                                                            │
│  End of session:                                           │
│    observations ──► generateSessionSummary()               │
│      type mapping: context→investigated, learning→learned, │
│      decision/tool_call→completed, error→investigated      │
│    summary written to summaries table                      │
│                                                            │
│  Nightly rollup:                                           │
│    session summaries ──► consolidateDay()                  │
│      idempotency check (skip if daily exists)              │
│      merge + Set dedup across sessions                     │
│    daily summary written                                   │
│                                                            │
│  Pruning:                                                  │
│    pruneObservations(retentionDays)                         │
│      delete observations older than N days                 │
│      KEEP any observation referenced by a summary          │
│      decrement storage_stats                               │
│                                                            │
│  Next session:                                             │
│    buildSessionContext(store, project, agentId)             │
│      latest daily summary → "Yesterday:" system prompt     │
│      ≤200 tokens budget, next_steps only                   │
└────────────────────────────────────────────────────────────┘
```

### Memory Security Invariants

The memory store enforces three security invariants independently of the executor pipeline:

| # | Invariant | Enforcement |
|---|-----------|-------------|
| 4 | **Memory size caps** | Per-entry: 10KB content. Global: 100MB quota tracked in `storage_stats`. Reject with `MemoryQuotaError` on overflow. |
| 5 | **No credential storage** | `validateObservation()` runs `redactAllCredentials()` + `redactPII()` from `@sentinel/types`. If content after scrubbing is *only* redaction markers, reject with `ContentOnlySensitiveError`. |
| — | **Deduplication** | SHA-256 content hash + 30-second dedup window prevents identical writes from flooding the store. |

### Memory Store Data Model

**Three SQLite tables + two virtual tables:**

| Table | Type | Purpose |
|-------|------|---------|
| `observations` | Regular | Core storage — project, session, agent, type, title, content, content_hash, concepts (JSON), files_involved (JSON) |
| `summaries` | Regular | Consolidated summaries — scope (session/daily/weekly), period range, investigated/learned/completed/next_steps arrays |
| `storage_stats` | Regular | Single-row quota tracker — `total_bytes` updated on insert/prune |
| `observations_fts` | FTS5 virtual | Full-text index on title + content + concepts, Porter stemming tokenizer |
| `observations_vec` | vec0 virtual | Vector index — 384-dim float embeddings, KNN via `WHERE embedding MATCH ? AND k = ?` |

---

## Confirmation Subsystem (Parallel State Machine)

```
     CLI Host Terminal                    Executor
     ─────────────────                    ────────
     ┌─────────────────┐
     │ Poller (500ms)  │
     │ GET /pending-   │───────────►  returns pending[]
     │ confirmations   │
     └────────┬────────┘
              │ for each new manifestId:
     ┌────────▼────────┐
     │ Display tool,   │
     │ category, params│
     │                 │
     │ if irreversible:│
     │ "⚠ CANNOT BE    │
     │  UNDONE"        │
     │                 │
     │ "Approve? (y/n)"│
     └────────┬────────┘
              │ user answers (or 5-min timeout → auto-deny)
     ┌────────▼────────┐
     │ POST /confirm/  │───────────►  resolves Promise
     │ {manifestId}    │              executor resumes
     │ {approved: bool}│              /execute handler
     └─────────────────┘
```

This runs as a concurrent process on the **host** (not inside Docker), ensuring the trust anchor for confirmation decisions is outside the agent's reach. The executor auto-denies after 5 minutes to prevent resource exhaustion from hung confirmations (pen test finding).

---

## Executor Endpoints

| Endpoint | Method | Auth | Body Limit | Purpose |
|----------|--------|------|-----------|---------|
| `/health` | GET | No | — | Liveness probe (`{ status: "ok", version: "0.1.0" }`) |
| `/agent-card` | GET | Yes | — | AgentCard metadata for orchestration |
| `/tools` | GET | Yes | — | List registered tools (builtin + MCP) |
| `/pending-confirmations` | GET | Yes | — | Query pending user confirmations |
| `/proxy/llm/*` | ALL | Yes | 25MB | SSRF-protected LLM proxy (Anthropic, OpenAI, Google) |
| `/execute` | POST | Yes | 10MB | Main tool execution — guard pipeline + tool handler |
| `/confirm/:manifestId` | POST | Yes | — | Approve/deny pending confirmation |

Auth is constant-time SHA-256 bearer token comparison. The `/health` endpoint is exempt. All authenticated endpoints return `X-Sentinel-Signature` (HMAC) and `X-Request-ID` headers.

---

## Key Files Reference

| Pipeline Step | File | Key Function |
|---------------|------|-------------|
| Startup/entrypoint | `packages/executor/src/entrypoint.ts` | startup sequence |
| HTTP server + middleware | `packages/executor/src/server.ts` | `createApp()` |
| Request ID | `packages/executor/src/request-id.ts` | `requestIdMiddleware()` |
| Body size limits | `packages/executor/src/server.ts` | inline middleware |
| HMAC response signing | `packages/executor/src/response-signer.ts` | `createResponseSigner()` |
| Auth | `packages/executor/src/auth-middleware.ts` | `createAuthMiddleware()` |
| Core pipeline | `packages/executor/src/router.ts` | `handleExecute()` |
| Policy classifier | `packages/policy/src/classifier.ts` | `classify()` |
| Rate limiter | `packages/policy/src/rate-limiter.ts` | `RateLimiter.check()` |
| Loop guard | `packages/policy/src/loop-guard.ts` | `LoopGuard.check()` |
| Content moderation | `packages/executor/src/moderation/scanner.ts` | `moderate()` |
| Email injection scanner | `packages/executor/src/moderation/email-scanner.ts` | `scanEmailContent()` |
| Credential filter | `packages/executor/src/credential-filter.ts` | `filterCredentials()` |
| PII scrubber | `packages/executor/src/pii-scrubber.ts` | `scrubPII()` |
| SSRF guard | `packages/executor/src/ssrf-guard.ts` | `checkSsrf()` |
| LLM proxy | `packages/executor/src/llm-proxy.ts` | `createLlmProxyHandler()` |
| SSE credential filter | `packages/executor/src/sse-credential-filter.ts` | `SseCredentialFilter` |
| GWS tools + scoping | `packages/executor/src/tools/gws.ts` | `GwsAgentScopes` |
| GWS auth/token | `packages/executor/src/tools/gws-auth.ts` | OAuth refresh |
| GWS integrity | `packages/executor/src/tools/gws-integrity.ts` | supply chain verification |
| GWS validation | `packages/executor/src/tools/gws-validation.ts` | input validation |
| Credential patterns | `packages/types/src/credential-patterns.ts` | `redactAll()` |
| Audit logger | `packages/audit/src/logger.ts` | `AuditLogger.log()` |
| Ed25519 signing | `packages/crypto/src/signing.ts` | `sign()`, `verify()` |
| useCredential helper | `packages/crypto/src/use-credential.ts` | `useCredential()` |
| Credential vault | `packages/crypto/src/vault.ts` | `CredentialVault` |
| Agent loop | `packages/agent/src/loop.ts` | `agentLoop()` |
| Manifest builder | `packages/agent/src/manifest-builder.ts` | `buildManifest()` |
| Confirmation TUI | `packages/cli/src/confirmation-tui.ts` | `startConfirmationPoller()` |
| Memory store | `packages/memory/src/store.ts` | `MemoryStore` |

---

## Changes from Phase 1.5

| Area | Phase 1.5 (PR #9) | Phase 2 (Wave 2.2c) |
|------|-------------------|---------------------|
| **Tests** | 542 | 847 |
| **Packages** | 8 | 9 (+`crypto-native` Rust N-API) |
| **HTTP middleware** | None | Request ID, body size limits, HMAC signing |
| **Action categories** | read/write/dangerous | +write-irreversible |
| **Confirmation** | Infinite wait | 5-min timeout, auto-deny |
| **Credential patterns** | 21 credential + 9 PII | Same count, now with 3-pass encoding + depth limit |
| **GWS integration** | None | Tool handler, per-agent scoping, email scanner |
| **Credential access** | `decrypt()`/`retrieve()` | `useCredential()` callback pattern |
| **Audit entries** | 1 per execution | 2 per execution (pending + final) |
| **Ed25519 signing** | Optional | Mandatory (auto-keygen in constructor) |
| **Classifier defense** | None | ReDoS protection (200 char cap, nested quantifier detection) |
| **Response integrity** | None | HMAC-SHA256 on all responses |
| **Streaming defense** | None | SSE credential filter on LLM proxy |
| **Email defense** | None | Email injection scanner + pre-send credential gate |

> **Numbering note**: The diagram uses *step numbers* (1-15) for the linear processing sequence. The narrative uses *phase numbers* (0-11) which group related steps thematically. The mapping is:
> - Phases 0-3: Before trust boundary (no step numbers — agent-side)
> - Phase 4: Steps 1-4 (HTTP middleware)
> - Phase 5: Steps 5-8 (guard pipeline)
> - Phase 6: Decision routing (branching, not a single step)
> - Phases 7-9: Steps 9-14 (moderation + execution + output filters)
> - Phase 10: Step 15 (final audit)
> - Phase 11: Return (no step number)
