# Execution Delegation Design — Closing the Execution Plane Gap

**Date:** 2026-03-16
**Status:** Proposed
**Scope:** OpenClaw plugin hook API change + Sentinel plugin implementation

---

## 1. Current Defense Posture

Sentinel protects OpenClaw agents across four security planes:

| Plane | Mechanism | Status |
|-------|-----------|--------|
| **Credential** | Encrypted vault, `useCredential()` callback scope, buffer zeroization, credential pattern stripping | Enforced |
| **Decision** | `/classify` endpoint, deterministic policy, rate limiter, loop guard, HITL confirmation via `/confirm-only` | Enforced |
| **Network** | Docker `internal: true`, CONNECT tunnel proxy, egress proxy with domain-scoped credential binding, SSRF blocking | Enforced |
| **Execution** | `before_tool_call` hook can block — but OpenClaw executes the tool itself | **Advisory only** |

The first three planes are enforcement-level controls. The fourth — execution — is advisory: Sentinel classifies and can block, but when a tool is approved, OpenClaw executes it directly. This means:

- Sentinel's **credential filter** doesn't see execution results
- Sentinel's **PII scrubber** only catches results at the `tool_result_persist` hook (after the agent already saw them)
- Sentinel's **audit logger** records classification but not execution outcome
- Sentinel's **output truncation** is bypassed entirely

## 2. The Execution Gap

### What's controlled

```
Agent proposes tool call
    ↓
[before_tool_call] → Sentinel classifies → block / confirm / approve
    ↓ (if approved)
OpenClaw executes tool directly          ← GAP: Sentinel not involved
    ↓
[tool_result_persist] → Sentinel redacts  ← Too late: agent saw raw result
    ↓
[message_sending] → Sentinel redacts      ← Outbound only
```

### What should happen

```
Agent proposes tool call
    ↓
[before_tool_call] → Sentinel classifies → block / confirm / delegate
    ↓ (if delegated)
Sentinel executor runs the tool           ← Credential injection, SSRF check, audit
    ↓
Sentinel filters result                   ← Credential strip, PII redact, truncate
    ↓
Result returned to OpenClaw via hook      ← Agent only sees sanitized output
```

### Why Docker containment is the wrong lever

CLAUDE.md item 10 previously framed "Docker network isolation mitigates" as the answer. This is incorrect:

1. **Docker controls the network plane**, which is already handled by CONNECT proxy + egress proxy
2. **The execution gap is on the application plane** — OpenClaw's runtime calls tools using its own execution engine, regardless of network controls
3. **Container boundaries don't help** when the gap is between two processes that must communicate (plugin ↔ gateway) within the same trust boundary
4. Network isolation prevents credential exfiltration but doesn't prevent the agent from seeing unfiltered tool results in-process

Docker is necessary infrastructure (and already deployed), but it doesn't close this specific gap.

## 3. Proposed Hook API Change

### Current `BeforeToolCallResult`

```typescript
// register.ts — current OpenClaw hook return type
interface PluginHookBeforeToolCallResult {
    params?: Record<string, unknown>;  // Can modify params
    block?: boolean;                    // Can block execution
    blockReason?: string;              // Reason for blocking
}
```

### Proposed addition

```typescript
interface PluginHookBeforeToolCallResult {
    params?: Record<string, unknown>;
    block?: boolean;
    blockReason?: string;
    // NEW: If set, OpenClaw uses this as the tool result instead of executing
    result?: unknown;
}
```

When `result` is set and `block` is falsy, OpenClaw skips its own execution and uses the provided result directly. This is the minimal API change — one optional field.

### Why this is the right abstraction

1. **Backward compatible** — existing plugins return no `result` field, behavior unchanged
2. **Plugin-agnostic** — any plugin can delegate execution, not just Sentinel
3. **No new hook type** — reuses existing `before_tool_call` lifecycle
4. **Composable** — plugin can selectively delegate (e.g., only for `write` category tools)
5. **OpenClaw retains control** — the framework decides whether to honor `result`; it's not a forced override

### Upstream coordination

This requires a change to OpenClaw's plugin SDK. The proposal:

1. File issue on `openclaw/openclaw` describing the use case
2. Reference this design spec
3. Offer to submit the PR (minimal change in plugin hook dispatch)
4. The change is ~20 lines in OpenClaw's hook dispatch logic

## 4. What Sentinel Implements When Available

### Plugin changes (`register.ts`)

```typescript
// before_tool_call handler — with execution delegation
api.on("before_tool_call", async (event, ctx) => {
    const classification = await client.classify(tool, params, agentId, sessionId);

    if (classification.decision === "block") {
        return { block: true, blockReason: classification.reason };
    }

    if (classification.decision === "confirm") {
        const confirmation = await client.confirmOnly(tool, params, agentId, sessionId);
        if (confirmation.decision === "denied") {
            return { block: true, blockReason: "Denied by user" };
        }
    }

    // DELEGATE: Execute through Sentinel instead of OpenClaw
    const executionResult = await client.execute(tool, params, agentId, sessionId);
    return { result: executionResult.output };  // Sanitized by executor
});
```

### New executor endpoint

`POST /execute` — full execution pipeline:
1. Classify (reuses existing policy)
2. Inject credentials from vault (service-scoped)
3. Execute tool (sandboxed subprocess)
4. Audit log (with execution outcome)
5. Filter output (credential strip + PII redact + truncate)
6. Return sanitized result

This endpoint already exists conceptually in the executor's tool execution flow — it's the same pipeline used for Sentinel-native agents. The work is exposing it as an HTTP API with OpenClaw-compatible request/response shapes.

### Guard Client SDK extension

`@sentinel/guard-client` gets an `execute()` method alongside existing `classify()` and `filterOutput()`:

```typescript
interface GuardClient {
    classify(tool: string, params: object): Promise<ClassifyResult>;
    filterOutput(output: string): Promise<FilterResult>;
    confirmOnly(tool: string, params: object): Promise<ConfirmResult>;
    execute(tool: string, params: object): Promise<ExecuteResult>;  // NEW
}
```

## 5. Interim Defense Posture

Until the upstream hook change lands, Sentinel provides 6 defensive layers:

| Layer | Mechanism | What it catches |
|-------|-----------|-----------------|
| 1. Classification | `/classify` → deterministic policy | Blocks dangerous tools, rate-limits, loop detection |
| 2. Confirmation | `/confirm-only` → HITL web approval | User veto on write/irreversible actions |
| 3. Output redaction | `tool_result_persist` hook | Credentials and PII in persisted transcripts |
| 4. Message redaction | `message_sending` hook | Credentials and PII in outbound messages |
| 5. Network isolation | CONNECT proxy + egress proxy | Domain-scoped access, SSRF blocking, credential injection |
| 6. Credential isolation | Encrypted vault, never in agent env | Agent can't access raw credentials |

**What's not covered (the residual risk):**
- Agent sees unfiltered tool results in-process before `tool_result_persist` fires
- No execution audit trail (only classification audit)
- No credential injection for OpenClaw-executed tools (they use their own credential mechanisms)

**Risk assessment:** The residual risk is bounded because:
- Network isolation prevents exfiltration of any leaked data
- Credential patterns are stripped before persistence
- The agent is the LLM itself — it processes tool results but can't programmatically extract and exfiltrate them without network access
- HITL confirmation gates all write operations

## 6. Migration Path

### Before upstream change (current)

```
OpenClaw → [before_tool_call] → Sentinel classifies → approve/block
                                                         ↓ (if approved)
                                               OpenClaw executes tool
                                                         ↓
                               [tool_result_persist] → Sentinel redacts
```

- Sentinel role: **advisory classifier + output sanitizer**
- Execution: OpenClaw-controlled
- Audit: classification only

### After upstream change (target)

```
OpenClaw → [before_tool_call] → Sentinel classifies → block / delegate
                                                         ↓ (if delegated)
                                               Sentinel executes tool
                                                         ↓
                                               Sentinel filters result
                                                         ↓
                                          result returned via hook API
```

- Sentinel role: **execution proxy + classifier + sanitizer**
- Execution: Sentinel-controlled (for delegated tools)
- Audit: full lifecycle (classify → execute → filter → return)

### Selective delegation

Not all tools need delegation. The migration is incremental:

1. **Phase A:** Delegate `write` and `write-irreversible` tools (highest risk)
2. **Phase B:** Delegate `read` tools that access credentialed services
3. **Phase C:** Delegate all tools (full enforcement)

`read` tools with no credential requirements (e.g., `memory_search`) can remain OpenClaw-executed indefinitely — there's no security benefit to delegating them.

## 7. Alternatives Considered

### A. Monkey-patch OpenClaw's tool executor
**Rejected.** Fragile, breaks on updates, requires deep coupling to OpenClaw internals.

### B. Run OpenClaw inside Sentinel's executor process
**Rejected.** Violates two-process model. Sentinel's executor is the trusted boundary — running untrusted agent code inside it defeats the architecture.

### C. Use `block: true` and re-execute externally
**Rejected.** Blocking tells the LLM the tool failed — it will retry or hallucinate results. The agent needs to receive a real result, just one that came through Sentinel's pipeline.

### D. Accept advisory-only posture permanently
**Considered.** The 6-layer interim defense is strong enough for the current threat model (local Mac Mini, single user, no internet-facing endpoints). But it's not sufficient for cloud deployment or multi-tenant scenarios. The execution delegation path keeps those options open.

---

## References

- `packages/openclaw-plugin/src/register.ts` — Current hook registration
- `packages/openclaw-plugin/src/index.ts` — Plugin factory with `beforeToolCall`
- `packages/executor/src/routes/classify-endpoint.ts` — `/classify` endpoint
- `packages/executor/src/routes/confirm-endpoint.ts` — `/confirm-only` endpoint
- `packages/guard-client/src/index.ts` — Guard Client SDK
- OpenAI Equip architecture (CLAUDE.md §Notes from Mar. 15) — validates two-process model, domain-scoped binding
