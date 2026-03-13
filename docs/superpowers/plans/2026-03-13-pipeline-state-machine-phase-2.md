# Pipeline State Machine Phase 2 — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Write a standalone pipeline state machine document covering the full 20-step Sentinel request pipeline at 847 tests / 9 packages (post-Wave 2.2c).

**Architecture:** Documentation-only task. No code changes. Write one Markdown file (`docs/pipeline-state-machine-phase-2.md`) with 9 sections of ASCII art diagrams and narrative. Follow the Phase 1.5 template structure (`docs/pipeline-state-machine-phase-1.5.md`).

**Tech Stack:** Markdown, ASCII box-drawing characters (─│┌┐└┘├┤┬┴┼═╪►▼◄), monospace layout.

**Spec:** `docs/superpowers/specs/2026-03-13-pipeline-state-machine-phase-2-design.md`

---

## Chunk 1: Scaffold + Header + Main Diagram

### Task 1: Write Sections 1–2 (Header, Snapshot, Main State Machine Diagram)

**Files:**
- Create: `docs/pipeline-state-machine-phase-2.md`

**Reference files to consult:**
- Template: `docs/pipeline-state-machine-phase-1.5.md` (lines 1–161 for diagram style)
- Spec: `docs/superpowers/specs/2026-03-13-pipeline-state-machine-phase-2-design.md` (Sections 1–2)
- Source verification: `packages/executor/src/server.ts` (middleware order)

**Key differences from Phase 1.5 diagram:**
- Insert a new `HTTP MIDDLEWARE` box between TRUST BOUNDARY and GUARD PIPELINE, containing 4 steps: Request ID, Body Size Limits, HMAC Response Signer, Auth
- Guard pipeline renumbered to steps 5–8 (was 1–4). Step 8 (Policy Classify) adds `+ GWS classify + ReDoS guard` description
- Decision routing: CONFIRM box shows `(write/write-irreversible/dangerous)` instead of `(write/dangerous)`. AWAITING CONFIRMATION adds `(5-min timeout)` annotation
- Execution pipeline renumbered to steps 9–15 (was 6–10). Add step 10 "Audit: Pending" before tool execution. Step 15 "Audit: Final" after post-moderation
- GWS added to tool execute step alongside bash/read/write/MCP

- [ ] **Step 1: Write the header and snapshot block**

Write the file header matching Phase 1.5 format:

```markdown
# Sentinel Pipeline State Machine — Phase 2

> **Snapshot**: Post-Wave 2.2c (847 tests, 9 packages) — Ed25519 manifest signing, `write-irreversible` classification, GWS CLI integration, credential zeroization (`useCredential()`), HMAC response signing, body size limits, ReDoS-hardened classifier, dual audit entries (pending + final).
>
> **Master plan**: [`docs/plans/path-a-v2-adopt-openfang-primitives.md`](plans/path-a-v2-adopt-openfang-primitives.md)
>
> **Previous**: [`docs/pipeline-state-machine-phase-1.5.md`](pipeline-state-machine-phase-1.5.md) — Phase 1.5 pipeline (542 tests, 8 packages).
```

- [ ] **Step 2: Write the main ASCII state machine diagram**

Reproduce the full diagram in Phase 1.5 box-drawing style. The diagram has these layers top-to-bottom:

1. **HOST BOUNDARY** box — identical to Phase 1.5 (Rampart firewall, DENY/ASK/ALLOW)
2. **USER INPUT** box — identical
3. **AGENT PROCESS** box — identical (Add to Context → Call LLM → Text/Tool → Build Manifest → loop)
4. **TRUST BOUNDARY** line — identical (`═══ HTTP :3141 ═══`)
5. **EXECUTOR PROCESS** box — identical header
6. **HTTP MIDDLEWARE** box (NEW) — 4 steps in a row:
   ```
   │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
   │  │ 1.Request│→│ 2.Body   │→│ 3.HMAC   │→│ 4.Auth   │  │
   │  │ ID (UUID)│  │ Size     │  │ Response │  │ (SHA-256 │  │
   │  │         │  │ (10/25MB)│  │ Signer   │  │  const-  │  │
   │  │         │  │ →413     │  │          │  │  time)   │  │
   │  │         │  │          │  │          │  │ →401     │  │
   │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
   ```
7. **GUARD PIPELINE** box — same 4-column layout but numbered 5–8. Step 8 description changes to `(bash parse + GWS + config + ReDoS)`
8. **DECISION ROUTING** — add `write-irreversible` to CONFIRM box, add `(5-min timeout)` to AWAITING CONFIRMATION, add TIMEOUT alongside DENIED
9. **EXECUTION PIPELINE** — 7 steps in reverse-flow layout:
   ```
   │  ┌──────────┐  ┌─────────┐  ┌────────┐  ┌───────────┐  ┌──────────┐
   │  │14.Post-  │←│13.PII   │←│12.Cred │←│11.TOOL    │←│10.Audit  │←│ 9.Pre-   │
   │  │execute   │  │ Scrub   │  │ Filter │  │ EXECUTE   │  │ Pending  │  │execute   │
   │  │moderation│  │         │  │        │  │           │  │ (Merkle  │  │moderation│
   │  │          │  │         │  │        │  │           │  │ +Ed25519)│  │          │
   ```
   Note: This is 6 boxes plus a 7th for Audit: Final below.
10. **AUDIT LOG** box — `15. AUDIT LOG (Merkle chain + Ed25519, SQLite, pending + final entries)`
11. **RETURN** box — identical
12. **MEMORY STORE** subsystem — carried forward from Phase 1.5 (update from "PR #9, 542 tests" context)

- [ ] **Step 3: Verify middleware order and LLM proxy against source**

Read `packages/executor/src/server.ts` and confirm the middleware registration order matches the diagram (Request ID → Body Size → HMAC Signer → Auth). Note the actual line numbers for reference.

Also read `packages/executor/src/llm-proxy.ts` and confirm it uses `useCredential()` for vault-based API key injection (imported from `@sentinel/crypto`).

- [ ] **Step 4: Commit**

```bash
git add docs/pipeline-state-machine-phase-2.md
git commit -m "docs: add pipeline state machine Phase 2 — sections 1-2 (header + diagram)"
```

---

## Chunk 2: Security Model + Phase Breakdown (Phases 0–4)

### Task 2: Write Section 3 (Three-Layer Security Model)

**Files:**
- Modify: `docs/pipeline-state-machine-phase-2.md`

**Reference files to consult:**
- Template: `docs/pipeline-state-machine-phase-1.5.md` (lines 165–210 for structure)
- Spec: Section 3

- [ ] **Step 1: Write the three-layer ASCII box diagram**

Copy the Layer 1/2/3 box from Phase 1.5 and update:
- Layer 2: Add `HTTP middleware (body size, HMAC, request ID), ReDoS-hardened classifier, 5-min confirmation timeout` to the "What" field
- Layer 3: Add `SSE credential filter, email injection scanner, 3-pass encoding-aware redaction` to the "What" field

- [ ] **Step 2: Write the "What Rampart Provides" comparison table**

Carry forward the 11-row table from Phase 1.5 and add 5 new rows:
- Response integrity: HMAC-SHA256 signing (Sentinel) / N/A (Rampart)
- Request size limits: Body size per-route (Sentinel) / N/A (Rampart)
- GWS scoping: Per-agent service allow/deny (Sentinel) / N/A (Rampart)
- Email defense: Email injection scanner + pre-send credential gate (Sentinel) / N/A (Rampart)
- Streaming defense: SSE credential filter on LLM proxy (Sentinel) / N/A (Rampart)

- [ ] **Step 3: Commit**

```bash
git add docs/pipeline-state-machine-phase-2.md
git commit -m "docs: pipeline Phase 2 — section 3 (three-layer security model)"
```

### Task 3: Write Section 4, Phases 0–4 (Pipeline Phase Breakdown, first half)

**Files:**
- Modify: `docs/pipeline-state-machine-phase-2.md`

**Reference files to consult:**
- Template: `docs/pipeline-state-machine-phase-1.5.md` (lines 213–257)
- Spec: Section 4
- Source: `packages/executor/src/server.ts` (middleware), `packages/executor/src/request-id.ts`, `packages/executor/src/response-signer.ts`, `packages/executor/src/auth-middleware.ts`

- [ ] **Step 1: Write Phase 0 (Rampart Host Firewall)**

Carry forward from Phase 1.5 — unchanged.

- [ ] **Step 2: Write Phase 1 (User Input → Agent Context)**

Carry forward from Phase 1.5 — unchanged.

- [ ] **Step 3: Write Phase 2 (LLM Call via Proxy) — UPDATED**

Carry forward Phase 1.5 base and add:
- API keys now injected from vault via `useCredential()` callback pattern (not raw env vars)
- SSE credential filter (`packages/executor/src/sse-credential-filter.ts`) scrubs credentials from streaming LLM responses in real-time
- LLM proxy handler created via factory pattern: `createLlmProxyHandler(vault?, auditLogger?)`
- Reference file: `packages/executor/src/llm-proxy.ts`

- [ ] **Step 4: Write Phase 3 (Action Manifest Construction)**

Carry forward from Phase 1.5 — unchanged.

- [ ] **Step 5: Write Phase 4 (HTTP Middleware) — NEW**

This phase did not exist in Phase 1.5. Write narrative covering:

1. **Request ID** (`packages/executor/src/request-id.ts`, `requestIdMiddleware()`) — assigns UUID v4 to each request, stored in Hono context, returned as `X-Request-ID` response header. Enables request tracing across audit entries.

2. **Body Size Limits** (`packages/executor/src/server.ts`, inline middleware) — two-layer defense:
   - Layer 1: `Content-Length` header check (fast reject without reading body)
   - Layer 2: Actual body byte count verification (catches chunked transfer encoding bypass)
   - Limits: 10MB for `/execute`, 25MB for `/proxy/llm/*`
   - Gated behind `SENTINEL_DOCKER=true` to avoid breaking Hono test client
   - Returns 413 Payload Too Large

3. **HMAC Response Signer** (`packages/executor/src/response-signer.ts`, `createResponseSigner(hmacSecret)`) — computes HMAC-SHA256 of response body, sets `X-Sentinel-Signature` header. Enables agent to verify response integrity (detect MITM between containers). SSE responses get "streaming" marker (integrity via mTLS).

4. **Auth Middleware** (`packages/executor/src/auth-middleware.ts`, `createAuthMiddleware(authToken)`) — validates Bearer token using constant-time SHA-256 hash comparison. Skips `/health`. Returns 401 if no token configured in Docker (fail-safe default).

- [ ] **Step 6: Commit**

```bash
git add docs/pipeline-state-machine-phase-2.md
git commit -m "docs: pipeline Phase 2 — section 4 phases 0-4 (Rampart through HTTP middleware)"
```

---

## Chunk 3: Phase Breakdown (Phases 5–11) + Remaining Sections

### Task 4: Write Section 4, Phases 5–11 (Pipeline Phase Breakdown, second half)

**Files:**
- Modify: `docs/pipeline-state-machine-phase-2.md`

**Reference files to consult:**
- Template: `docs/pipeline-state-machine-phase-1.5.md` (lines 258–301)
- Spec: Section 4 (phases 5–11)
- Source: `packages/policy/src/classifier.ts`, `packages/executor/src/router.ts`, `packages/executor/src/tools/gws.ts`, `packages/executor/src/moderation/email-scanner.ts`

- [ ] **Step 1: Write Phase 5 (Guard Pipeline) — UPDATED**

Carry forward Phase 1.5 table format (4 rows) and update:
- Step 8 (Policy Classifier): Categories now include `write-irreversible` alongside `read`/`write`/`dangerous`
- Bash parsing + **GWS tool classification** (`classifyGwsTool()`) — irreversible for send, dangerous for delete
- ReDoS protection: regex pattern length capped at 200 chars, nested quantifier detection returns `true` (fail-safe restrictive)
- Reference: `packages/policy/src/classifier.ts`

- [ ] **Step 2: Write Phase 6 (Decision Routing) — UPDATED**

Carry forward Phase 1.5 base and add:
- Fourth category: `write-irreversible` maps to `confirm` with additional TUI warning "cannot be undone"
- 5-minute confirmation timeout: auto-deny after 300s to prevent resource exhaustion (pen test finding)
- Timeout path: same as DENIED — audit entry + error response

- [ ] **Step 3: Write Phase 7 (Pre-Execute Content Moderation)**

Carry forward from Phase 1.5 (promoted from sub-phase to explicit phase). Same scanner, same modes.

- [ ] **Step 4: Write Phase 8 (Tool Execution) — UPDATED**

Carry forward Phase 1.5 tool list and add:
- **`gws`** (`packages/executor/src/tools/gws.ts`) — Google Workspace operations:
  - OAuth token injected from vault via `useCredential()`, set as `GOOGLE_WORKSPACE_CLI_TOKEN` env var
  - Per-agent scoping: `GwsAgentScopes` with `denyServices` checked before `allowedServices` (deny-first)
  - Email injection scanning (`packages/executor/src/moderation/email-scanner.ts`) on outbound email content
  - Pre-send credential gating: `containsCredential()` check before subprocess spawn
  - Supply chain integrity verification (`packages/executor/src/tools/gws-integrity.ts`)
- Dual audit entry pattern: pending entry BEFORE execution (step 10), final entry AFTER (step 15)

- [ ] **Step 5: Write Phase 9 (Output Sanitization) — UPDATED**

Carry forward Phase 1.5 3-row table and update:
- Credential Filter row: now 21 credential patterns (source: `packages/types/src/credential-patterns.ts`), 3-pass encoding-aware approach (`redactAllCredentialsWithEncoding()`): plaintext → base64 decode → URL decode. Recursive depth limit (4 levels, 64KB input cap). PEM keys, JWT, Stripe keys added since Phase 1.5.
- PII Scrubber row: 9 PII patterns (SSN, phone ×3, email, salary ×2, LinkedIn, GitHub profile URLs)
- Post-execute Moderation: unchanged

- [ ] **Step 6: Write Phase 10 (Audit Logging) — UPDATED**

Carry forward Phase 1.5 base and update:
- **Two entries per execution**: "pending" entry written BEFORE tool execution (crash/hang coverage — pen test H1 finding), "final" entry written AFTER with success/failure + duration
- Ed25519 signing is now mandatory: `AuditLogger` auto-generates keypair in constructor (`loadOrGenerateSigningKey()`). Signing key stored as `audit-signing.key` (0o600) alongside audit DB — never inside SQLite.
- `verifyChain(publicKey?)` validates both hash chain AND signatures when public key provided
- Merkle chain: `entry_hash` = SHA-256 of `[prev_hash, id, timestamp, tool, agentId, result]`

- [ ] **Step 7: Write Phase 11 (Return to Agent)**

Carry forward from Phase 1.5 — unchanged. Note that response now includes `X-Sentinel-Signature` (HMAC) and `X-Request-ID` headers.

- [ ] **Step 8: Commit**

```bash
git add docs/pipeline-state-machine-phase-2.md
git commit -m "docs: pipeline Phase 2 — section 4 phases 5-11 (guards through return)"
```

### Task 5: Write Sections 5–7 (Memory Store, Confirmation, Endpoints)

**Files:**
- Modify: `docs/pipeline-state-machine-phase-2.md`

**Reference files to consult:**
- Template: `docs/pipeline-state-machine-phase-1.5.md` (lines 304–452)
- Spec: Sections 5–7

- [ ] **Step 1: Write Section 5 (Memory Store Subsystem)**

Carry forward from Phase 1.5 (lines 304–408). Update snapshot references:
- Replace "PR #9, 542 tests" with current context (847 tests, 9 packages)
- Keep all diagrams, tables, and narrative structure identical (no functional changes in Waves 2.1–2.2c)

- [ ] **Step 2: Write Section 6 (Confirmation Subsystem) — UPDATED**

Carry forward Phase 1.5 ASCII diagram (lines 413–432) and update:
- Add `write-irreversible` display: between "Display tool, category, params" and "Approve?", insert:
  ```
  │ if irreversible:│
  │ "⚠ CANNOT BE    │
  │  UNDONE"        │
  ```
- Change "user answers" annotation to: `user answers (or 5min timeout → auto-deny)`
- Replace final paragraph: "there is no timeout (waits indefinitely)" → "The executor auto-denies after 5 minutes to prevent resource exhaustion from hung confirmations (pen test finding)."

- [ ] **Step 3: Write Section 7 (Executor Endpoints)**

Carry forward Phase 1.5 table (lines 441–449) and add:
- New column or footnote: "All authenticated endpoints return `X-Sentinel-Signature` (HMAC) and `X-Request-ID` headers"
- Add body size note: `/execute` max 10MB, `/proxy/llm/*` max 25MB

- [ ] **Step 4: Commit**

```bash
git add docs/pipeline-state-machine-phase-2.md
git commit -m "docs: pipeline Phase 2 — sections 5-7 (memory, confirmation, endpoints)"
```

### Task 6: Write Sections 8–9 (Key Files Reference, Changes from Phase 1.5)

**Files:**
- Modify: `docs/pipeline-state-machine-phase-2.md`

**Reference files to consult:**
- Spec: Sections 8–9
- All source files (verify paths exist before writing table)

- [ ] **Step 1: Write Section 8 (Key Files Reference)**

Write the full table with all pipeline steps mapped to source files:

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

Verify each file path exists before including it in the table. Remove or annotate any that don't exist.

- [ ] **Step 2: Write Section 9 (Changes from Phase 1.5)**

Write the comparison table per spec:

| Area | Phase 1.5 (PR #9) | Phase 2 (Wave 2.2c) |
|------|-------------------|---------------------|
| Tests | 542 | 847 |
| Packages | 8 | 9 (+`crypto-native` Rust N-API) |
| HTTP middleware | None | Request ID, body size limits, HMAC signing |
| Action categories | read/write/dangerous | +write-irreversible |
| Confirmation | Infinite wait | 5-min timeout, auto-deny |
| Credential patterns | 21 credential + 9 PII | Same count, now with 3-pass encoding + depth limit |
| GWS integration | None | Tool handler, per-agent scoping, email scanner |
| Credential access | `decrypt()`/`retrieve()` | `useCredential()` callback pattern |
| Audit entries | 1 per execution | 2 per execution (pending + final) |
| Ed25519 signing | Optional | Mandatory (auto-keygen in constructor) |
| Classifier defense | None | ReDoS protection (200 char cap, nested quantifier detection) |
| Response integrity | None | HMAC-SHA256 on all responses |
| Streaming defense | None | SSE credential filter on LLM proxy |
| Email defense | None | Email injection scanner + pre-send credential gate |

> Note: Last 3 rows (response integrity, streaming, email) expand beyond the spec's 11-row table — intentional since these are major Phase 2 additions worth calling out in the delta.

Include the numbering note (step numbers 1–15 vs phase numbers 0–11 mapping) from the spec.

- [ ] **Step 3: Commit**

```bash
git add docs/pipeline-state-machine-phase-2.md
git commit -m "docs: pipeline Phase 2 — sections 8-9 (key files + changes from Phase 1.5)"
```

### Task 7: Final verification and push

- [ ] **Step 1: Verify document completeness**

Check that the document has all 9 sections:
1. Header & Snapshot
2. Main State Machine Diagram (ASCII)
3. Three-Layer Security Model
4. Pipeline Phase Breakdown (Phases 0–11)
5. Memory Store Subsystem
6. Confirmation Subsystem
7. Executor Endpoints
8. Key Files Reference
9. Changes from Phase 1.5

- [ ] **Step 2: Verify all file paths in the document exist**

Run glob/grep to confirm every `packages/*/src/*.ts` path referenced in the document resolves to a real file.

- [ ] **Step 3: Verify ASCII art renders correctly**

View the document in a monospace terminal or editor. Confirm box-drawing characters (─│┌┐└┘├┤┬┴┼═╪►▼) align properly and boxes are rectangular. Check that the HTTP MIDDLEWARE and GUARD PIPELINE boxes have consistent column widths.

- [ ] **Step 4: Verify line count is in expected range**

Document should be 450–600 lines. If significantly over/under, review for bloat or missing sections.

- [ ] **Step 5: Push to remote**

```bash
git push origin main
```
