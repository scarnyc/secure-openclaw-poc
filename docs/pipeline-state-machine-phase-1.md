# Sentinel Pipeline State Machine

> **Snapshot**: Post-Phase 1 (PR #8, 490 tests) — Merkle audit, SSRF guard, loop guard, rate limiter, PII scrubber, auth middleware, output truncation, request ID tracking.
>
> **Master plan**: [`docs/plans/path-a-v2-adopt-openfang-primitives.md`](plans/path-a-v2-adopt-openfang-primitives.md) — full roadmap including Phase 2 (Google Workspace, OpenClaw agents, sqlite-vec, CopilotKit/ag-ui) and outstanding security gaps.

```
                          ┌──────────────────┐
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
    ┌──────────────────────────────▼──────────────────────────────┐
    │                     GUARD PIPELINE                          │
    │                     (fail-fast, sequential)                 │
    │                                                            │
    │  ┌─────────┐  ┌───────────┐  ┌──────────┐  ┌───────────┐  │
    │  │ 1.Validate│→│ 2.Rate    │→│ 3.Loop   │→│ 4.Policy  │  │
    │  │ Manifest │  │ Limiter   │  │ Guard    │  │ Classify  │  │
    │  │ (Zod)   │  │ (token    │  │ (SHA-256 │  │ (bash     │  │
    │  │         │  │  bucket)  │  │  fingerp)│  │  parse +  │  │
    │  │ →400    │  │ →422+audit│  │ →422+aud │  │  config)  │  │
    │  └─────────┘  └───────────┘  └──────────┘  └─────┬─────┘  │
    │                                                   │        │
    │                                          ┌────────▼──────┐ │
    │                                          │ 5. DECISION   │ │
    │                                          │    ROUTING    │ │
    │                                          └──┬─────┬───┬──┘ │
    │                                  ┌──────────┘     │   └──────────┐
    │                                  │                │              │
    │                             ┌────▼───┐    ┌──────▼─────┐  ┌─────▼──────┐
    │                             │ BLOCK  │    │AUTO_APPROVE│  │ CONFIRM    │
    │                             │→error  │    │(read ops)  │  │(write/     │
    │                             │+audit  │    │            │  │ dangerous) │
    │                             └────────┘    └──────┬─────┘  └─────┬──────┘
    │                                                  │              │
    │                                                  │    ┌─────────▼────────┐
    │                                                  │    │ AWAITING         │
    │                                                  │    │ CONFIRMATION     │
    │                                                  │    │ (Promise blocks) │
    │                                                  │    └────┬────────┬────┘
    │                                                  │         │        │
    │                                                  │   ┌─────▼──┐ ┌───▼────┐
    │                                                  │   │APPROVED│ │DENIED  │
    │                                                  │   └─────┬──┘ │→error  │
    │                                                  │         │    │+audit  │
    │                                                  ├─────────┘    └────────┘
    │                                                  │
    │  ┌──────────┐  ┌─────────┐  ┌────────┐  ┌───────▼───┐  ┌──────────┐
    │  │10.Post-  │←│ 9.PII   │←│ 8.Cred │←│ 7.TOOL    │←│ 6.Pre-   │
    │  │execute   │  │ Scrub   │  │ Filter │  │ EXECUTE   │  │execute   │
    │  │moderation│  │         │  │        │  │           │  │moderation│
    │  └────┬─────┘  └─────────┘  └────────┘  └───────────┘  └──────────┘
    │       │                                                            │
    │  ┌────▼──────────────────────────────────────────────────────────┐ │
    │  │ 11. AUDIT LOG (Merkle-chained SHA-256, SQLite append-only)   │ │
    │  └────┬─────────────────────────────────────────────────────────┘ │
    └───────┼──────────────────────────────────────────────────────────┘
            │
    ┌───────▼────────┐
    │ 12. RETURN     │
    │ ToolResult     │──────────► back to Agent (loop continues)
    └────────────────┘
```

---

## Pipeline Phase Breakdown

### Phase 1: User Input → Agent Context

The CLI (`packages/cli/src/commands/chat.ts`) orchestrates startup: unlocks the encrypted vault, starts the executor on `:3141`, spawns a confirmation poller (long-polls every 500ms), and launches the agent loop. User messages are added to `ConversationContext`, which auto-trims at ~100k tokens to stay within LLM limits.

### Phase 2: LLM Call (via Proxy)

The agent has **no internet access** (Docker `internal: true`). All LLM calls route through the executor's `/proxy/llm/*` endpoint, which:
- Validates the target host against an allowlist (Anthropic, OpenAI, Google)
- Runs the **SSRF guard** to block private IPs and cloud metadata endpoints
- Injects API keys from the executor's environment (the agent never sees them)

The LLM proxy is a key security primitive — it means the agent process literally cannot exfiltrate data to arbitrary URLs. Even if the LLM is prompt-injected into trying to call a malicious endpoint, the proxy's host allowlist blocks it.

### Phase 3: Action Manifest Construction

When the LLM decides to use a tool, the agent builds an **ActionManifest** — a typed JSON envelope with UUID, timestamp, tool name, parameters, sessionId, and agentId. This is the only way the agent can request side effects.

### Phase 4: Guard Pipeline (Steps 1-4)

The executor runs four sequential guards, failing fast on any block:

| Step | Guard | What it does |
|------|-------|-------------|
| 1 | **Manifest Validation** | Zod schema parse — rejects malformed requests (400) |
| 2 | **Rate Limiter** | Token bucket algorithm, 60 req/min per agentId — prevents runaway agents |
| 3 | **Loop Guard** | SHA-256 fingerprints `(tool, params)` pairs — blocks if same call repeated 5x in 60s |
| 4 | **Policy Classifier** | Categorizes as `read`/`write`/`dangerous` via bash command parsing + config lookup |

### Phase 5: Decision Routing

The policy classification maps to one of three actions:

- **`block`** → immediate rejection + audit entry (e.g., `rm -rf /`)
- **`auto_approve`** → skip confirmation, proceed to execution (read-only ops when configured)
- **`confirm`** → enter the human-in-the-loop confirmation state

### Phase 6: Content Moderation (Pre-Execute)

If `SENTINEL_MODERATION_MODE=enforce`, the scanner checks serialized parameters for prompt injection and data exfiltration patterns **before** the tool runs. In `warn` mode it logs but doesn't block.

### Phase 7: Tool Execution

The executor runs the tool handler:
- **`bash`** — shell execution with deny-list checks, optional firejail sandboxing (Linux)
- **`read_file`** — path allowlist + `O_NOFOLLOW` symlink protection
- **`write_file`** — path allowlist + `O_NOFOLLOW` + TOCTOU mitigation
- **MCP tools** — forwarded to registered MCP servers

### Phases 8-10: Output Sanitization

Three filters clean the tool output before it reaches the agent:

| Step | Filter | Protects against |
|------|--------|-----------------|
| 8 | **Credential Filter** | API keys (Anthropic, OpenAI, GitHub, AWS, Slack, etc.) → `[REDACTED]` |
| 9 | **PII Scrubber** | SSN, phone, email, salary, LinkedIn URLs → `[PII_REDACTED]` |
| 10 | **Post-execute Moderation** | Prompt injection in tool output |

All patterns come from a single source of truth in `packages/types/src/credential-patterns.ts`.

### Phase 11: Audit Logging (Merkle Chain)

Every request — regardless of outcome — gets an append-only SQLite record with:
- Full provenance: `manifestId`, `sessionId`, `agentId`, `tool`, `category`
- Outcome: `decision`, `result` (success/failure/denied/blocked), `duration_ms`
- **Merkle chain**: each entry's `entry_hash` = SHA-256 of `[prev_hash, id, timestamp, ...]`, creating a tamper-evident log

### Phase 12: Return to Agent

The `ToolResult` (sanitized output, success flag, duration) returns to the agent, which adds it to the conversation context and loops back to the LLM for the next reasoning step.

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
     │ "Approve? (y/n)"│
     └────────┬────────┘
              │ user answers
     ┌────────▼────────┐
     │ POST /confirm/  │───────────►  resolves Promise
     │ {manifestId}    │              executor resumes
     │ {approved: bool}│              /execute handler
     └─────────────────┘
```

This runs as a concurrent process on the **host** (not inside Docker), ensuring the trust anchor for confirmation decisions is outside the agent's reach.
