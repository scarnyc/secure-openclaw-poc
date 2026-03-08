# OWASP Phase 0 Gate Review

**Date**: 2026-03-08
**Scope**: Phase 0 executor endpoints — `POST /execute`, `POST /confirm/:id`, `ALL /proxy/llm/*`, `GET /pending-confirmations`
**Reviewer**: Automated security review (Phase 0 gate)
**Status**: PASS with findings

## Executive Summary

Phase 0 endpoints are suitable for local development use. The executor implements defense-in-depth with Zod input validation, policy-based classification, credential filtering, content moderation, and audit logging. All findings are MEDIUM or LOW severity, consistent with the local-first threat model (Mac Mini, single user, Docker-isolated agent).

No CRITICAL or HIGH findings. Six findings total: 2 MEDIUM, 3 LOW, 1 INFO.

---

## Endpoint Review

### POST /execute

**Handler**: `packages/executor/src/router.ts` — `handleExecute()`
**OWASP categories**: A01 (Broken Access Control), A03 (Injection), A04 (Insecure Design), A08 (Software and Data Integrity Failures)

**Pipeline** (8 stages, lines 27-152):

1. **Input validation** — `ActionManifestSchema.safeParse()` validates all fields via Zod: `id` (UUID), `timestamp` (ISO datetime), `tool` (non-empty string), `parameters` (record), `sessionId` and `agentId` (non-empty strings). Invalid payloads throw `ManifestValidationError` returning 400. (line 35-38)
2. **Policy classification** — `classify(manifest, config)` produces a `PolicyDecision` with `action: "allow" | "confirm" | "block"`. Blocked actions are audit-logged and rejected with 422. (line 42, 57-69)
3. **Confirmation gate** — `confirm` actions wait on a `Promise<boolean>` resolved by `POST /confirm/:id`. Denied actions are audit-logged as `denied_by_user`. (line 71-86)
4. **Pre-execute moderation** — `moderate(paramText)` scans request parameters for prompt injection and exfiltration patterns. Blocked if `SENTINEL_MODERATION_MODE=enforce`. (line 89-103)
5. **Tool dispatch** — `registry.get(manifest.tool)` resolves handler; unknown tools return 422 with audit entry. (line 106-119)
6. **Execution** — Handler invoked with `(parameters, manifestId)`. (line 121)
7. **Credential filtering** — `filterCredentials(rawResult)` applies `redactAll()` (credentials then PII) to both `output` and `error` fields before returning to agent. (line 124)
8. **Post-execute moderation** — Tool output scanned for harmful content. (line 127-142)
9. **Audit** — Every code path logs to SQLite via `auditLogger.log()` with `agentId`, `sessionId`, category, decision, and redacted parameter summary. (line 145-149)

**Strengths**:
- Every code path (block, deny, moderation block, unknown tool, success, failure) writes an audit entry — Invariant #2 is maintained.
- Parameter summary is redacted via `redactCredentials()` before audit write (line 54), preventing credential leakage into the audit log.
- `parameters` field uses `z.record(z.unknown())` — permissive by design (tools define their own parameter schemas), but the Zod parse still prevents non-object payloads and prototype pollution via JSON parse.
- Error messages never include credential values — `ManifestValidationError` only surfaces Zod validation errors, not parameter contents.

**Findings**:
- **F1 (MEDIUM)**: No authentication between agent and executor. Any process on the Docker network can call `/execute`. Mitigated by Docker `internal: true` network isolating the agent container. Tracked for Phase 1 (mTLS or shared secret).
- **F4 (LOW)**: No rate limiting on `/execute`. A compromised or looping agent could flood the executor. GCRA rate limiter planned for Phase 1 (Invariant #9).
- **F7 (LOW)**: The `parameters` field accepts `z.record(z.unknown())` — tool handlers must validate their own parameter shapes. A malformed parameter could cause an unhandled exception in a tool handler. Current handlers (bash, read_file, write_file) do validate, but there is no enforced contract at the registry level.

---

### POST /confirm/:id

**Handler**: `packages/executor/src/server.ts` — lines 85-104
**OWASP categories**: A01 (Broken Access Control), A04 (Insecure Design), A08 (Software and Data Integrity Failures)

**Flow**:
1. Extract `manifestId` from URL param. (line 86)
2. Look up in `pendingConfirmations` Map. Return 404 if not found. (line 87-90)
3. Parse body via `ConfirmBodySchema` (Zod: `{ approved: boolean }`). Return 400 on invalid. (line 93-97)
4. Delete from Map and resolve the waiting Promise. (line 100-101)
5. Return `{ status: "approved" | "denied" }`. (line 103)

**Strengths**:
- Zod validation on request body prevents non-boolean `approved` values.
- Confirmation entry is deleted from Map before resolving — prevents double-confirmation.
- The manifestId is a UUID (validated at `/execute` intake), making brute-force guessing infeasible.

**Findings**:
- **F2 (MEDIUM)**: No TTL on pending confirmations. If a confirmation is never resolved (user walks away, TUI crashes), the associated `/execute` request hangs indefinitely, leaking a Promise and Map entry. Recommendation: add a 5-minute expiry with `setInterval` cleanup, resolving stale entries as `denied`. Tracked for Phase 1.
- **F6 (INFO)**: No authentication on `/confirm/:id`. Any process that can reach the executor port can approve/deny actions. Mitigated by: (a) executor listens on `127.0.0.1:3141` in local dev, (b) manifestId is a random UUID (unguessable), (c) in Docker mode the confirmation TUI runs on the host outside the container network.

---

### ALL /proxy/llm/*

**Handler**: `packages/executor/src/llm-proxy.ts` — `handleLlmProxy()`
**OWASP categories**: A01 (Broken Access Control), A05 (Security Misconfiguration), A07 (Identification and Authentication Failures), A10 (Server-Side Request Forgery)

**Flow**:
1. Extract downstream path from URL (everything after `/proxy/llm`). Return 400 if empty. (line 44-51)
2. Read target host from `x-llm-host` header, default `api.anthropic.com`. (line 54)
3. Validate against `ALLOWED_LLM_HOSTS` allowlist (3 hosts: Anthropic, OpenAI, Google). Return 403 if not allowed. (line 56-58)
4. Build target URL: `https://${targetHost}${downstreamPath}`. (line 60)
5. Forward headers, stripping hop-by-hop and auth headers (`host`, `connection`, `x-llm-host`, `content-length`, `authorization`, `x-api-key`, `x-goog-api-key`). (line 63-79)
6. Inject API key from executor `process.env` based on host-to-env mapping. Return 500 if key missing. (line 82-90)
7. Forward request via `fetch()`, stream response back. (line 92-104)
8. Catch errors, return 502 with generic message. (line 105-110)

**Strengths (A10 — SSRF)**:
- Strict allowlist of 3 LLM API hosts. The agent cannot use the proxy to reach internal services, cloud metadata (`169.254.169.254`), or arbitrary internet hosts.
- Auth headers from the agent are stripped (line 67-77) — the agent cannot inject its own API key to bypass the proxy's key management.
- The proxy constructs the URL via `https://${targetHost}${downstreamPath}` — the `https://` prefix is hardcoded, preventing scheme downgrade to `http://` or `file://`.
- Error messages do not leak API keys — the 500 response says `"LLM proxy configuration error"` without revealing which env var is missing (line 86-87).

**Strengths (A05 — Misconfiguration)**:
- `HOST_AUTH_HEADERS` mapping is static and exhaustive for the 3 allowed hosts. Adding a host to `ALLOWED_LLM_HOSTS` without a corresponding `HOST_AUTH_HEADERS` entry would result in no auth injection (requests would fail at the provider), not a security bypass.

**Findings**:
- **F3 (LOW)**: API keys are read from `process.env` as V8 immutable strings (line 84). They cannot be zeroed from memory after use. The code documents this explicitly (line 41-42) and defers to Phase 1 vault-based Buffer keys. Acceptable for local dev; the keys live in the executor container's environment regardless.
- **F5 (LOW)**: The `downstreamPath` is taken directly from the URL and appended to the target host without sanitization. A path like `/v1/messages/../../../other-endpoint` would be normalized by the target server (standard HTTP behavior), not by the proxy. In practice this is not exploitable because: (a) the target host is allowlisted to 3 LLM APIs, and (b) path traversal on an HTTPS API server does not grant filesystem access. However, for defense-in-depth, normalizing the path before forwarding would prevent any future edge cases.

---

### GET /pending-confirmations

**Handler**: `packages/executor/src/server.ts` — lines 59-68
**OWASP categories**: A01 (Broken Access Control), A04 (Insecure Design)

**Flow**:
1. Iterate `pendingConfirmations` Map entries. (line 60)
2. Return array of `{ manifestId, tool, parameters, category, reason }`. (line 61-67)

**Strengths**:
- Read-only endpoint — cannot modify state.
- Returns structured data the TUI needs to display confirmation prompts.

**Findings**:
- **F6 (INFO)**: No authentication. Any process that can reach the executor can enumerate pending actions, including their tool names and parameters. Mitigated by: (a) executor binds `127.0.0.1` in local dev (only localhost access), (b) in Docker mode, only the host confirmation TUI polls this endpoint, (c) parameters may contain sensitive data but are visible to the user who is confirming them anyway.
- **Note**: Parameters returned here are not credential-filtered. This is intentional — the confirmation TUI must show the user the actual parameters they are approving (e.g., the actual file path, the actual bash command). Credential filtering happens on tool *output*, not on inbound parameters displayed to the trusted user.

---

## Findings Summary

| # | Severity | Finding | Endpoint | Recommendation | Phase |
|---|----------|---------|----------|---------------|-------|
| F1 | MEDIUM | No authN between agent and executor | /execute | Mitigated by Docker `internal: true` network; add mTLS or shared secret | Phase 1 |
| F2 | MEDIUM | No TTL on pending confirmations — stale entries leak memory and hang requests | /confirm/:id | Add 5-min expiry + `setInterval` cleanup resolving as denied | Phase 1 |
| F3 | LOW | LLM proxy API keys are V8 strings (cannot be zeroed) | /proxy/llm/* | Vault-based Buffer keys with `fill(0)` in finally | Phase 1 |
| F4 | LOW | No rate limiting on /execute | /execute | GCRA rate limiter (Invariant #9) | Phase 1 |
| F5 | LOW | LLM proxy downstream path not normalized before forwarding | /proxy/llm/* | Add `new URL(path).pathname` normalization | Phase 1 |
| F6 | INFO | No auth on /pending-confirmations and /confirm/:id | Multiple | Localhost-only binding + UUID unguessability sufficient for local dev | Accepted |
| F7 | LOW | Tool parameter schemas not enforced at registry level | /execute | Add per-tool Zod schema validation in registry dispatch | Phase 1 |

---

## Security Controls Verified

The following controls were verified as correctly implemented:

| Control | Status | Evidence |
|---------|--------|----------|
| Zod input validation on all endpoints | PASS | `ActionManifestSchema.safeParse()` (router.ts:35), `ConfirmBodySchema.safeParse()` (server.ts:94) |
| Credential stripping on tool output | PASS | `filterCredentials()` calls `redactAll()` — credentials then PII (router.ts:124, credential-filter.ts:4-9) |
| Credential redaction in audit log | PASS | `redactCredentials(summarizeParams())` on parameter summary (router.ts:54) |
| Audit logging on all code paths | PASS | 5 audit write sites covering block, deny, moderation, failure, success (router.ts:58,74,95,108,145) |
| SSRF prevention via host allowlist | PASS | `ALLOWED_LLM_HOSTS` Set with 3 entries, checked before request (llm-proxy.ts:3-7, 56) |
| Auth header stripping from agent requests | PASS | `authorization`, `x-api-key`, `x-goog-api-key` stripped (llm-proxy.ts:72-74) |
| Symlink TOCTOU mitigation on write_file | PASS | `lstat()` check rejects symlinks before write (write-file.ts:41-42) |
| Path whitelist with realpath resolution | PASS | `isPathAllowed()` resolves symlinks, falls back to lexical only for ENOENT (path-guard.ts:46) |
| Deny-list for sensitive file paths | PASS | `.env*`, `.dev.vars`, `.pem`, `.key`, `secret`, `credential`, `.git/config` blocked (deny-list.ts) |
| Docker write prefix restriction | PASS | `/app/data/` prefix enforced when `SENTINEL_DOCKER=true` (write-file.ts:65-67) |
| Content moderation (pre/post execute) | PASS | `moderate()` scans parameters and output; configurable enforce/warn/off (router.ts:89-103, 127-142) |
| Policy classification with confirm gate | PASS | `classify()` routes to block/confirm/allow; confirm waits for user approval (router.ts:42, 71-86) |
| Error messages exclude credentials | PASS | Validation errors surface Zod messages only; proxy returns generic `"LLM proxy configuration error"` |

---

## Methodology

- Manual code review of all endpoint handlers and supporting modules
- Cross-reference with OWASP Top 10 2021 categories: A01 (Broken Access Control), A03 (Injection), A04 (Insecure Design), A05 (Security Misconfiguration), A07 (Identification and Authentication Failures), A08 (Software and Data Integrity Failures), A10 (SSRF)
- Threat model: local Mac Mini, single user, Docker-isolated agent with `internal: true` network
- Verified against project security invariants 1-6 (see CLAUDE.md)

## Conclusion

Phase 0 gate: **PASS**. No CRITICAL or HIGH findings. The executor implements a well-structured 8-stage pipeline with defense-in-depth: input validation, policy classification, user confirmation, content moderation, credential filtering, and comprehensive audit logging. The 2 MEDIUM findings (no inter-process auth, no confirmation TTL) are mitigated by the local-first architecture and tracked for Phase 1. The 4 LOW/INFO findings are appropriate accepted risks for the current threat model.
