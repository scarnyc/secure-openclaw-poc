# Pipeline State Machine Phase 2 — Design Spec

> **Date**: 2026-03-13
> **Output**: `docs/pipeline-state-machine-phase-2.md`
> **Template**: `docs/pipeline-state-machine-phase-1.5.md`
> **Audience**: Security auditors, new developers, architecture reference

## Goal

Create a standalone document describing the full Sentinel request pipeline at the current codebase state (847 tests, 9 packages, post-Wave 2.2c). Follows the Phase 1.5 template structure but is fully self-contained — no cross-referencing required.

## Document Structure

### Section 1: Header & Snapshot
- Title: "Sentinel Pipeline State Machine — Phase 2 (Wave 2.2c)"
- Snapshot block: 847 tests, 9 packages, key capabilities added since Phase 1.5
- Links to master plan and previous pipeline doc

### Section 2: Main State Machine Diagram (ASCII Art)
Full ASCII box-art diagram showing the 20-step pipeline:

**Host Boundary** (Rampart firewall — unchanged from Phase 1.5)

**Agent Process** (untrusted):
- Add to Conversation Context
- Call LLM (via proxy)
- Text → display / Tool call → Build Action Manifest
- POST /execute across trust boundary

**HTTP Middleware Layer** (new — did not exist in Phase 1.5):
1. Request ID (UUID assignment)
2. Body Size Limits (10MB for /execute, 25MB for /proxy/llm/*)
3. HMAC Response Signer (SHA-256 signs all response bodies)
4. Auth Middleware (constant-time SHA-256 Bearer token comparison)

**Guard Pipeline** (fail-fast, sequential):
5. Validate Manifest (Zod schema → 400)
6. Rate Limiter (GCRA, 60 req/min per-agent → 422+audit)
7. Loop Guard (SHA-256 fingerprint, warn@3 block@5 in 60s → 422+audit)
8. Policy Classify (bash parse + GWS classify + config lookup + ReDoS guard)

**Decision Routing**:
- BLOCK → error + audit
- AUTO_APPROVE (read ops when configured)
- CONFIRM (write / write-irreversible / dangerous)
  - AWAITING CONFIRMATION (5-min timeout, auto-deny)
  - write-irreversible shows "cannot be undone" TUI warning
  - APPROVED → continue / DENIED|TIMEOUT → error + audit

**Execution & Post-Processing**:
9. Pre-execute Content Moderation (prompt injection + exfiltration scanning)
10. Audit: Pending entry (Merkle chain + Ed25519 signature)
11. Tool Execute (bash/gws/read/write/MCP handlers)
12. Credential Filter (46 patterns, 3-pass encoding-aware, depth-limited)
13. PII Scrubber (SSN, phone, email, salary → [PII_REDACTED])
14. Post-execute Content Moderation
15. Audit: Final entry (success/failure + duration, Merkle + Ed25519)

**Return**: ToolResult → back to Agent loop

### Section 3: Three-Layer Security Model
ASCII box diagram + comparison table, same structure as Phase 1.5.

**Layer 1: Rampart (Host Boundary)** — unchanged. 45 standard + 3 project policies.

**Layer 2: Sentinel Executor (Application Boundary)** — expanded:
- HTTP middleware: body size limits (chunked transfer bypass defense), HMAC response signing, request ID
- Policy classifier: GWS tool classification, `write-irreversible` category, ReDoS protection (200 char cap, nested quantifier detection)
- Confirmation: 5-minute timeout (resource exhaustion defense)

**Layer 3: Sentinel Output Filters (Data Boundary)** — expanded:
- Credential filter: 46 patterns (up from ~30), 3-pass encoding (plaintext → base64 → URL decode), recursive depth limit (4 levels)
- SSE credential filter for streaming LLM proxy responses
- Email injection scanner + pre-send credential gating
- PEM key detection, JWT tokens, Stripe keys added

Updated Sentinel vs Rampart comparison table adds rows for: response integrity (HMAC), request size limits, GWS scoping, email defense, streaming defense.

### Section 4: Pipeline Phase Breakdown (Narrative)
One subsection per phase with what/where/why narrative:

| Phase | Title | Status vs Phase 1.5 |
|-------|-------|---------------------|
| 0 | Rampart Host Firewall | Unchanged |
| 1 | User Input → Agent Context | Unchanged |
| 2 | LLM Call (via Proxy) | Updated — SSE credential filter, useCredential() vault injection |
| 3 | Action Manifest Construction | Unchanged |
| 4 | HTTP Middleware | **New** — Request ID, Body Size, HMAC Signer, Auth |
| 5 | Guard Pipeline | Updated — ReDoS, write-irreversible, GWS classifier |
| 6 | Decision Routing | Updated — 5-min timeout, write-irreversible TUI warning |
| 7 | Pre-Execute Content Moderation | Unchanged (promoted to explicit phase) |
| 8 | Tool Execution | Updated — GWS handler, email scanner, per-agent scoping |
| 9 | Output Sanitization | Updated — 46 patterns, 3-pass encoding, depth limit |
| 10 | Audit Logging | Updated — dual entries (pending+final), Ed25519 mandatory |
| 11 | Return to Agent | Unchanged |

### Section 5: Memory Store Subsystem
Carried forward verbatim from Phase 1.5. No changes in Waves 2.1–2.2c.
- Write path (validate → scrub → dedup → quota → insert → embed)
- Read path (FTS5 + vector KNN → reciprocal rank fusion)
- Consolidation path (session summary → daily rollup → prune → context builder)
- Memory security invariants table
- Data model (3 tables + 2 virtual tables)

### Section 6: Confirmation Subsystem
Updated ASCII diagram showing:
- 5-minute timeout with auto-deny (was infinite)
- write-irreversible "CANNOT BE UNDONE" warning in TUI display
- Same host-side trust anchor, Promise blocking, concurrent poller

### Section 7: Executor Endpoints
Same 7-endpoint table from Phase 1.5. Note that all authenticated endpoints now return `X-Sentinel-Signature` (HMAC) and `X-Request-ID` headers.

### Section 8: Key Files Reference (New)
25-row table mapping pipeline steps to source files and key functions. Developer onboarding lookup.

## Implementation Notes

- Output file: `docs/pipeline-state-machine-phase-2.md`
- ASCII art style must match Phase 1.5 box-drawing characters
- All code references must be verified against actual file paths
- Estimated document size: ~450-500 lines
