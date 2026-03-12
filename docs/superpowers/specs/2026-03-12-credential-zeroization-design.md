# V8 String Lifetime Minimization & Credential Zeroization

**Date:** 2026-03-12
**Status:** Draft
**Branch:** `security/credential-zeroization`

## Problem

When Sentinel decrypts a credential and converts it to a JavaScript string (for HTTP headers, CLI args), V8 interns it as an immutable object that cannot be overwritten. Every Node.js app has this problem. Sentinel mitigates with `decryptToBuffer()` + immediate zeroization, but the moment you call `.toString()`, you're in V8 territory.

**Current gaps:**
- `getKeyFromVault()` in `llm-proxy.ts` returns a string that persists as `apiKey` until the handler function returns — longer than necessary
- `forwardHeaders` retains the auth header (with credential) after `fetch()` completes — never cleaned up
- `chat.ts` uses deprecated `vault.retrieve()` — string lives for entire session
- GWS OAuth tokens bypass the vault entirely (macOS Keychain) — no Sentinel-managed lifecycle
- `decrypt()` and `vault.retrieve()` return V8 strings with no deprecation signal

## Solution

### 1. `useCredential<T>()` Helper

New callback-scoped credential accessor in `packages/crypto/src/use-credential.ts`:

```typescript
export async function useCredential<T>(
  vault: CredentialVault,
  serviceId: string,
  fn: (cred: Record<string, string>) => T | Promise<T>,
): Promise<T> {
  const buf = vault.retrieveBuffer(serviceId);
  try {
    const parsed: Record<string, string> = JSON.parse(buf.toString("utf8"));
    return await fn(parsed);
  } finally {
    buf.fill(0);
  }
}
```

**Contract:** Callbacks MUST NOT store credential values outside their scope (no assignment to outer variables, no caching). Enforced by code review.

**Why callback scope matters:** The `parsed` object (containing credential strings) is only reachable within `fn`'s closure. Once `fn` returns and the `finally` block executes, the Buffer is deterministically zeroed and the V8 strings become unreachable — eligible for GC and heap reuse. This is the best we can do given V8's immutable string model.

### 2. LLM Proxy Hardening

Refactor `llm-proxy.ts` to scope credential strings to the minimum lifetime:

```typescript
// Move fetch() inside useCredential callback
await useCredential(vault, `llm/${targetHost}`, async (cred) => {
  const value = authConfig.prefix ? `${authConfig.prefix}${cred.key}` : cred.key;
  forwardHeaders.set(authConfig.headerName, value);
  const response = await fetch(targetUrl, { headers: forwardHeaders, ... });
  forwardHeaders.delete(authConfig.headerName);  // Remove credential post-fetch
  return response;
});
```

- Credential strings scoped to callback — unreachable after return
- Auth header deleted from `forwardHeaders` after fetch (previously never cleaned up)
- Env var fallback preserved outside `useCredential` for non-vault deployments

### 3. GWS Vault Migration

Move Google OAuth tokens from macOS Keychain into Sentinel vault:

**Vault service ID:** `google/oauth`
**Stored fields:** `{ clientId, clientSecret, refreshToken, accessToken, expiresAt }`

**On-demand refresh:** Before each GWS call, check `expiresAt`. If expired (with 60s buffer), use `refreshToken` to obtain a new `accessToken` via `https://oauth2.googleapis.com/token`, store updated tokens back to vault.

**Token injection:** Pass access token to `gws` subprocess via env var or CLI flag (determined by spike — Task 0).

**New file:** `packages/executor/src/tools/gws-auth.ts`

### 4. CLI Chat Migration

Replace `vault.retrieve("anthropic")` with `vault.retrieveBuffer()` in `chat.ts`. The `apiKey` string lifetime is inherently session-long (passed to `agentLoop`), which is an acceptable tradeoff for local dev — Docker mode uses the executor's vault-managed proxy.

### 5. API Deprecation

- `decrypt()`: `@deprecated` JSDoc + one-time `console.warn`
- `vault.retrieve()`: `@deprecated` JSDoc + one-time `console.warn`
- Migrate `vault.open()` password verifier from `decrypt()` to `decryptToBuffer()` (enables zero callers of deprecated API)

## Security Invariants

All 12 existing invariants maintained. This work strengthens:
- **Invariant 1** (no credentials in tool responses) — credential strings have shorter lifetimes
- **Invariant 5** (no credential storage in memory) — `useCredential` enforces scoped access

## Entrypoint Ordering Change

`packages/executor/src/entrypoint.ts` currently creates the tool registry (line 23) before opening the vault (line 31). For GWS vault injection, reorder: open vault first, then create registry with vault parameter.

## SSRF Note

The OAuth refresh endpoint (`oauth2.googleapis.com`) is called from trusted executor code, not through the LLM proxy. SSRF guard only applies to the proxy handler, so no allowlist change needed.

## Testing Strategy

~20 new tests across 4 test files:
- `useCredential`: buffer zeroed after callback; buffer zeroed on throw; async works; return value propagated
- LLM proxy: auth header removed post-fetch; useCredential pattern used
- GWS auth: valid token returned without refresh; expired triggers refresh; refresh failure propagated
- Deprecation: warning fires once per function; functions still work
