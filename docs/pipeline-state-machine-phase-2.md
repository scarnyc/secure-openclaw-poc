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
