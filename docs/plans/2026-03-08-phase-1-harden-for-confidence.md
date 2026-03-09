# Phase 1: Harden for Confidence — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add security patterns that catch real attacks — tamper-evident audit, SSRF protection, loop detection, rate limiting, output truncation — so Sentinel can run unattended with confidence.

**Architecture:** Eight new modules wired into the existing 8-stage router pipeline. Merkle chaining extends AuditLogger. SSRF guard wraps the LLM proxy DNS resolution. Loop guard and rate limiter are new policy-layer gates inserted before classification. Output truncation caps bash stdout. All modules are pure functions with zero external dependencies beyond `node:crypto` and `node:dns`.

**Tech Stack:** TypeScript, Vitest, better-sqlite3, node:crypto (SHA-256, timingSafeEqual), node:dns (SSRF), Hono middleware (UUID)

**Already complete (skip):** Bash deny-list, PII scrubber (regex-based in `credential-patterns.ts`)

---

## Task 1: Merkle Hash-Chain Audit

**Files:**
- Modify: `packages/audit/src/logger.ts`
- Modify: `packages/types/src/audit.ts`
- Test: `packages/audit/src/logger.test.ts`

### Step 1: Write failing tests

Add to `packages/audit/src/logger.test.ts`:

```typescript
import { createHash } from "node:crypto";

describe("Merkle hash-chain audit", () => {
  it("first entry has prev_hash of 64 zeros", () => {
    const entry = makeEntry({ tool: "bash" });
    auditLogger.log(entry);
    const rows = auditLogger.getRecent(1);
    expect(rows[0].prevHash).toBe("0".repeat(64));
    expect(rows[0].entryHash).toBeDefined();
    expect(rows[0].entryHash!.length).toBe(64);
  });

  it("second entry chains to first entry hash", () => {
    auditLogger.log(makeEntry({ tool: "bash" }));
    auditLogger.log(makeEntry({ tool: "read_file" }));
    const rows = auditLogger.getRecent(10);
    // getRecent returns DESC order
    const [second, first] = rows;
    expect(second.prevHash).toBe(first.entryHash);
  });

  it("verifyChain detects tampered row", () => {
    auditLogger.log(makeEntry({ tool: "bash" }));
    auditLogger.log(makeEntry({ tool: "read_file" }));
    auditLogger.log(makeEntry({ tool: "bash" }));

    // Tamper with middle row
    const db = (auditLogger as any).db;
    db.prepare("UPDATE audit_log SET tool = 'TAMPERED' WHERE rowid = 2").run();

    const result = auditLogger.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(1);
  });

  it("verifyChain passes for untampered log", () => {
    auditLogger.log(makeEntry({ tool: "bash" }));
    auditLogger.log(makeEntry({ tool: "read_file" }));
    const result = auditLogger.verifyChain();
    expect(result.valid).toBe(true);
  });

  it("verifyChain returns valid for empty log", () => {
    const result = auditLogger.verifyChain();
    expect(result.valid).toBe(true);
  });
});
```

### Step 2: Run tests to verify they fail

Run: `pnpm --filter @sentinel/audit test`
Expected: FAIL — `prevHash`, `entryHash`, `verifyChain` don't exist

### Step 3: Implement Merkle chaining in AuditLogger

Modify `packages/audit/src/logger.ts`:

1. Add columns to `CREATE_TABLE`:
```sql
prev_hash TEXT NOT NULL DEFAULT '',
entry_hash TEXT NOT NULL DEFAULT ''
```

2. Add migration for existing DBs (ALTER TABLE):
```typescript
private migrate(): void {
  const columns = this.db!.pragma("table_info(audit_log)") as Array<{ name: string }>;
  const colNames = new Set(columns.map((c) => c.name));
  if (!colNames.has("prev_hash")) {
    this.db!.exec("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''");
    this.db!.exec("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''");
  }
}
```

3. Add `computeEntryHash()`:
```typescript
function computeEntryHash(prevHash: string, id: string, tool: string, category: string, decision: string, paramsSummary: string, result: string): string {
  const payload = `${prevHash}|${id}|${tool}|${category}|${decision}|${paramsSummary}|${result}`;
  return createHash("sha256").update(payload).digest("hex");
}
```

4. Modify `log()` to use a transaction — read last entry_hash, compute new hash, insert with both hashes.

5. Add `verifyChain()` method:
```typescript
verifyChain(): { valid: boolean; brokenAtIndex?: number } {
  const rows = this.getDb().prepare(
    "SELECT id, tool, category, decision, parameters_summary, result, prev_hash, entry_hash FROM audit_log ORDER BY rowid ASC"
  ).all() as Array<{ id: string; tool: string; category: string; decision: string; parameters_summary: string; result: string; prev_hash: string; entry_hash: string }>;

  let expectedPrev = "0".repeat(64);
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    if (row.prev_hash !== expectedPrev) return { valid: false, brokenAtIndex: i };
    const computed = computeEntryHash(row.prev_hash, row.id, row.tool, row.category, row.decision, row.parameters_summary, row.result);
    if (computed !== row.entry_hash) return { valid: false, brokenAtIndex: i };
    expectedPrev = row.entry_hash;
  }
  return { valid: true };
}
```

6. Update `AuditRow` interface and `rowToEntry` to include `prevHash` and `entryHash`.

7. Update `AuditEntry` type in `packages/types/src/audit.ts` to include optional `prevHash` and `entryHash`.

### Step 4: Run tests to verify they pass

Run: `pnpm --filter @sentinel/audit test`
Expected: PASS

### Step 5: Commit

```bash
git add packages/audit/src/logger.ts packages/audit/src/logger.test.ts packages/types/src/audit.ts
git commit -m "feat(audit): add Merkle hash-chain for tamper-evident logging (Invariant #7)"
```

---

## Task 2: SSRF Guard

**Files:**
- Create: `packages/executor/src/ssrf-guard.ts`
- Test: `packages/executor/src/ssrf-guard.test.ts`

### Step 1: Write failing tests

Create `packages/executor/src/ssrf-guard.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { isPrivateUrl, validateUrlNotPrivate } from "./ssrf-guard.js";

describe("SSRF guard", () => {
  it("blocks localhost URLs", async () => {
    await expect(validateUrlNotPrivate("http://127.0.0.1:8080/api")).rejects.toThrow("SSRF");
  });

  it("blocks 0.0.0.0", async () => {
    await expect(validateUrlNotPrivate("http://0.0.0.0/")).rejects.toThrow("SSRF");
  });

  it("blocks private 10.x.x.x range", async () => {
    await expect(validateUrlNotPrivate("http://10.0.0.1/")).rejects.toThrow("SSRF");
  });

  it("blocks private 172.16.x.x range", async () => {
    await expect(validateUrlNotPrivate("http://172.16.0.1/")).rejects.toThrow("SSRF");
  });

  it("blocks private 192.168.x.x range", async () => {
    await expect(validateUrlNotPrivate("http://192.168.1.1/")).rejects.toThrow("SSRF");
  });

  it("blocks cloud metadata endpoint", async () => {
    await expect(validateUrlNotPrivate("http://169.254.169.254/latest/meta-data/")).rejects.toThrow("SSRF");
  });

  it("blocks IPv6 loopback", async () => {
    await expect(validateUrlNotPrivate("http://[::1]/")).rejects.toThrow("SSRF");
  });

  it("allows public IP", () => {
    // Synchronous check against IP string
    expect(isPrivateUrl("https://api.anthropic.com")).toBe(false);
  });

  it("blocks file:// protocol", async () => {
    await expect(validateUrlNotPrivate("file:///etc/passwd")).rejects.toThrow("SSRF");
  });
});
```

### Step 2: Run tests to verify they fail

Run: `pnpm --filter @sentinel/executor test -- ssrf-guard`
Expected: FAIL — module doesn't exist

### Step 3: Implement SSRF guard

Create `packages/executor/src/ssrf-guard.ts`:

```typescript
import { resolve4, resolve6 } from "node:dns/promises";

const PRIVATE_RANGES = [
  { start: 0x0a000000, end: 0x0affffff },   // 10.0.0.0/8
  { start: 0xac100000, end: 0xac1fffff },   // 172.16.0.0/12
  { start: 0xc0a80000, end: 0xc0a8ffff },   // 192.168.0.0/16
  { start: 0x7f000000, end: 0x7fffffff },   // 127.0.0.0/8
  { start: 0xa9fe0000, end: 0xa9feffff },   // 169.254.0.0/16 (link-local + cloud metadata)
  { start: 0x00000000, end: 0x00000000 },   // 0.0.0.0
];

function ipToInt(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function isPrivateIp(ip: string): boolean {
  // IPv6 loopback
  if (ip === "::1" || ip === "0:0:0:0:0:0:0:1") return true;
  // IPv4
  const num = ipToInt(ip);
  return PRIVATE_RANGES.some((r) => num >= r.start && num <= r.end);
}

export function isPrivateUrl(urlStr: string): boolean {
  try {
    const url = new URL(urlStr);
    if (url.protocol !== "http:" && url.protocol !== "https:") return true;
    const hostname = url.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
    return isPrivateIp(hostname);
  } catch {
    return true; // invalid URLs are treated as private (blocked)
  }
}

export async function validateUrlNotPrivate(urlStr: string): Promise<void> {
  try {
    const url = new URL(urlStr);

    // Block non-HTTP protocols
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error(`SSRF blocked: protocol ${url.protocol} not allowed`);
    }

    const hostname = url.hostname.replace(/^\[|\]$/g, "");

    // Direct IP check
    if (isPrivateIp(hostname)) {
      throw new Error(`SSRF blocked: private IP ${hostname}`);
    }

    // DNS resolution check (hostname could resolve to private IP)
    try {
      const addresses = await resolve4(hostname);
      for (const addr of addresses) {
        if (isPrivateIp(addr)) {
          throw new Error(`SSRF blocked: ${hostname} resolves to private IP ${addr}`);
        }
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("SSRF")) throw err;
      // DNS resolution failed for IPv4, try IPv6
    }

    try {
      const addresses = await resolve6(hostname);
      for (const addr of addresses) {
        if (isPrivateIp(addr)) {
          throw new Error(`SSRF blocked: ${hostname} resolves to private IPv6 ${addr}`);
        }
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("SSRF")) throw err;
      // No IPv6, that's fine
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith("SSRF")) throw err;
    throw new Error(`SSRF blocked: invalid URL`);
  }
}
```

### Step 4: Run tests to verify they pass

Run: `pnpm --filter @sentinel/executor test -- ssrf-guard`
Expected: PASS

### Step 5: Commit

```bash
git add packages/executor/src/ssrf-guard.ts packages/executor/src/ssrf-guard.test.ts
git commit -m "feat(executor): add SSRF guard — block private IPs, localhost, cloud metadata (Invariant #8)"
```

---

## Task 3: Loop Guard

**Files:**
- Create: `packages/policy/src/loop-guard.ts`
- Test: `packages/policy/src/loop-guard.test.ts`
- Modify: `packages/policy/src/index.ts` (export)

### Step 1: Write failing tests

Create `packages/policy/src/loop-guard.test.ts`:

```typescript
import { describe, expect, it, beforeEach } from "vitest";
import { LoopGuard, type LoopGuardDecision } from "./loop-guard.js";

describe("Loop guard", () => {
  let guard: LoopGuard;

  beforeEach(() => {
    guard = new LoopGuard({ maxHistory: 5, warnThreshold: 3, blockThreshold: 5 });
  });

  it("allows first call", () => {
    const result = guard.check("agent-1", "bash", { command: "ls" });
    expect(result.action).toBe("allow");
  });

  it("warns after warnThreshold identical calls", () => {
    for (let i = 0; i < 3; i++) {
      guard.check("agent-1", "bash", { command: "ls" });
    }
    const result = guard.check("agent-1", "bash", { command: "ls" });
    expect(result.action).toBe("warn");
  });

  it("blocks after blockThreshold identical calls", () => {
    for (let i = 0; i < 5; i++) {
      guard.check("agent-1", "bash", { command: "ls" });
    }
    const result = guard.check("agent-1", "bash", { command: "ls" });
    expect(result.action).toBe("block");
  });

  it("tracks agents independently", () => {
    for (let i = 0; i < 5; i++) {
      guard.check("agent-1", "bash", { command: "ls" });
    }
    const result = guard.check("agent-2", "bash", { command: "ls" });
    expect(result.action).toBe("allow");
  });

  it("different parameters reset the count", () => {
    for (let i = 0; i < 4; i++) {
      guard.check("agent-1", "bash", { command: "ls" });
    }
    guard.check("agent-1", "bash", { command: "pwd" }); // different
    const result = guard.check("agent-1", "bash", { command: "ls" });
    // count should include both old + new
    expect(result.action).not.toBe("block");
  });

  it("detects ping-pong pattern (alternating identical calls)", () => {
    // A-B-A-B-A-B pattern
    for (let i = 0; i < 3; i++) {
      guard.check("agent-1", "bash", { command: "ls" });
      guard.check("agent-1", "bash", { command: "pwd" });
    }
    const result = guard.check("agent-1", "bash", { command: "ls" });
    expect(result.action).toBe("warn");
    expect(result.reason).toContain("ping-pong");
  });

  it("reset clears agent history", () => {
    for (let i = 0; i < 5; i++) {
      guard.check("agent-1", "bash", { command: "ls" });
    }
    guard.reset("agent-1");
    const result = guard.check("agent-1", "bash", { command: "ls" });
    expect(result.action).toBe("allow");
  });
});
```

### Step 2: Run tests to verify they fail

Run: `pnpm --filter @sentinel/policy test -- loop-guard`
Expected: FAIL — module doesn't exist

### Step 3: Implement loop guard

Create `packages/policy/src/loop-guard.ts`:

```typescript
import { createHash } from "node:crypto";

export interface LoopGuardConfig {
  maxHistory: number;      // how many hashes to keep per agent (default: 30)
  warnThreshold: number;   // identical call count to start warning (default: 5)
  blockThreshold: number;  // identical call count to block (default: 10)
}

export interface LoopGuardDecision {
  action: "allow" | "warn" | "block";
  reason?: string;
  count: number;
}

const DEFAULT_CONFIG: LoopGuardConfig = {
  maxHistory: 30,
  warnThreshold: 5,
  blockThreshold: 10,
};

function hashCall(tool: string, params: Record<string, unknown>): string {
  const payload = JSON.stringify({ tool, params });
  return createHash("sha256").update(payload).digest("hex");
}

export class LoopGuard {
  private config: LoopGuardConfig;
  private history: Map<string, string[]> = new Map(); // agentId -> hash[]

  constructor(config: Partial<LoopGuardConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  check(agentId: string, tool: string, params: Record<string, unknown>): LoopGuardDecision {
    const hash = hashCall(tool, params);
    const agentHistory = this.history.get(agentId) ?? [];

    agentHistory.push(hash);
    // Trim to maxHistory
    if (agentHistory.length > this.config.maxHistory) {
      agentHistory.splice(0, agentHistory.length - this.config.maxHistory);
    }
    this.history.set(agentId, agentHistory);

    // Count consecutive identical calls (most recent)
    const identicalCount = this.countConsecutiveIdentical(agentHistory, hash);

    if (identicalCount >= this.config.blockThreshold) {
      return { action: "block", reason: `Loop detected: ${identicalCount} identical calls`, count: identicalCount };
    }

    // Check ping-pong: A-B-A-B pattern in last 6 entries
    const pingPong = this.detectPingPong(agentHistory);
    if (pingPong) {
      return { action: "warn", reason: "Loop detected: ping-pong pattern", count: identicalCount };
    }

    if (identicalCount >= this.config.warnThreshold) {
      return { action: "warn", reason: `Repeated call: ${identicalCount} identical calls`, count: identicalCount };
    }

    return { action: "allow", count: identicalCount };
  }

  reset(agentId: string): void {
    this.history.delete(agentId);
  }

  private countConsecutiveIdentical(history: string[], hash: string): number {
    let count = 0;
    for (let i = history.length - 1; i >= 0; i--) {
      if (history[i] === hash) count++;
      else break;
    }
    return count;
  }

  private detectPingPong(history: string[]): boolean {
    if (history.length < 6) return false;
    const last6 = history.slice(-6);
    // Check A-B-A-B-A-B pattern
    const a = last6[0];
    const b = last6[1];
    if (a === b) return false;
    return last6.every((h, i) => h === (i % 2 === 0 ? a : b));
  }
}
```

### Step 4: Run tests to verify they pass

Run: `pnpm --filter @sentinel/policy test -- loop-guard`
Expected: PASS

### Step 5: Export from index and commit

Add to `packages/policy/src/index.ts`:
```typescript
export { LoopGuard, type LoopGuardConfig, type LoopGuardDecision } from "./loop-guard.js";
```

```bash
git add packages/policy/src/loop-guard.ts packages/policy/src/loop-guard.test.ts packages/policy/src/index.ts
git commit -m "feat(policy): add loop guard with ping-pong detection (Invariant #11)"
```

---

## Task 4: GCRA Rate Limiter

**Files:**
- Create: `packages/policy/src/rate-limiter.ts`
- Test: `packages/policy/src/rate-limiter.test.ts`
- Modify: `packages/policy/src/index.ts` (export)

### Step 1: Write failing tests

Create `packages/policy/src/rate-limiter.test.ts`:

```typescript
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RateLimiter } from "./rate-limiter.js";

describe("GCRA rate limiter", () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    vi.useFakeTimers();
    // 10 requests per second, burst of 3
    limiter = new RateLimiter({ period: 1000, limit: 10, burst: 3 });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("allows requests within rate", () => {
    expect(limiter.check("agent-1").allowed).toBe(true);
    expect(limiter.check("agent-1").allowed).toBe(true);
    expect(limiter.check("agent-1").allowed).toBe(true);
  });

  it("rejects requests exceeding burst", () => {
    for (let i = 0; i < 3; i++) {
      expect(limiter.check("agent-1").allowed).toBe(true);
    }
    expect(limiter.check("agent-1").allowed).toBe(false);
  });

  it("allows requests after waiting", () => {
    for (let i = 0; i < 3; i++) {
      limiter.check("agent-1");
    }
    expect(limiter.check("agent-1").allowed).toBe(false);

    // Advance time by one emission interval (1000ms / 10 = 100ms)
    vi.advanceTimersByTime(100);
    expect(limiter.check("agent-1").allowed).toBe(true);
  });

  it("tracks agents independently", () => {
    for (let i = 0; i < 3; i++) {
      limiter.check("agent-1");
    }
    expect(limiter.check("agent-1").allowed).toBe(false);
    expect(limiter.check("agent-2").allowed).toBe(true);
  });

  it("returns retryAfter when rate limited", () => {
    for (let i = 0; i < 3; i++) {
      limiter.check("agent-1");
    }
    const result = limiter.check("agent-1");
    expect(result.allowed).toBe(false);
    expect(result.retryAfterMs).toBeGreaterThan(0);
  });
});
```

### Step 2: Run tests to verify they fail

Run: `pnpm --filter @sentinel/policy test -- rate-limiter`
Expected: FAIL — module doesn't exist

### Step 3: Implement GCRA rate limiter

Create `packages/policy/src/rate-limiter.ts`:

```typescript
export interface RateLimiterConfig {
  period: number;   // time window in ms (e.g., 1000 = 1 second)
  limit: number;    // max requests per period
  burst: number;    // max burst above steady rate
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterMs?: number;
}

/**
 * Generic Cell Rate Algorithm (GCRA) rate limiter.
 * Tracks Theoretical Arrival Time (TAT) per agent.
 */
export class RateLimiter {
  private config: RateLimiterConfig;
  private tat: Map<string, number> = new Map(); // agentId -> TAT timestamp
  private emissionInterval: number; // ms between allowed requests at steady rate

  constructor(config: RateLimiterConfig) {
    this.config = config;
    this.emissionInterval = config.period / config.limit;
  }

  check(agentId: string, now: number = Date.now()): RateLimitResult {
    const burstWindow = this.emissionInterval * this.config.burst;
    const currentTat = this.tat.get(agentId) ?? now;

    const newTat = Math.max(currentTat, now) + this.emissionInterval;
    const allowAt = newTat - burstWindow;

    if (allowAt > now) {
      return { allowed: false, retryAfterMs: Math.ceil(allowAt - now) };
    }

    this.tat.set(agentId, newTat);
    return { allowed: true };
  }
}
```

### Step 4: Run tests to verify they pass

Run: `pnpm --filter @sentinel/policy test -- rate-limiter`
Expected: PASS

### Step 5: Export from index and commit

Add to `packages/policy/src/index.ts`:
```typescript
export { RateLimiter, type RateLimiterConfig, type RateLimitResult } from "./rate-limiter.js";
```

```bash
git add packages/policy/src/rate-limiter.ts packages/policy/src/rate-limiter.test.ts packages/policy/src/index.ts
git commit -m "feat(policy): add GCRA rate limiter — per-agent burst control (Invariant #9)"
```

---

## Task 5: Output Truncation

**Files:**
- Modify: `packages/executor/src/tools/bash.ts`
- Test: `packages/executor/src/tools/bash.test.ts` (add test)

### Step 1: Write failing test

Add to `packages/executor/src/tools/bash.test.ts`:

```typescript
describe("output truncation", () => {
  it("truncates bash output exceeding 50KB", async () => {
    // Generate >50KB of output using printf
    const result = await executeBash(
      { command: `printf '%0.sx' $(seq 1 60000)` },
      "test-manifest"
    );
    expect(result.output).toBeDefined();
    expect(result.output!.length).toBeLessThanOrEqual(51200 + 100); // 50KB + truncation message
    if (result.output!.length > 100) {
      expect(result.output).toContain("[TRUNCATED]");
    }
  });
});
```

### Step 2: Run tests to verify it fails

Run: `pnpm --filter @sentinel/executor test -- bash.test`
Expected: FAIL — output is not truncated

### Step 3: Add truncation constant and logic to bash.ts

In `packages/executor/src/tools/bash.ts`, add:

```typescript
const MAX_OUTPUT_BYTES = 50 * 1024; // 50KB

function truncateOutput(output: string, maxBytes: number): string {
  if (Buffer.byteLength(output) <= maxBytes) return output;
  const truncated = Buffer.from(output).subarray(0, maxBytes).toString("utf-8");
  return `${truncated}\n\n[TRUNCATED: output exceeded ${maxBytes} bytes]`;
}
```

Then modify the output assembly (around line 166) to use `truncateOutput`:

```typescript
const rawOutput = [result.stdout, result.stderr].filter(Boolean).join("\n");
const output = truncateOutput(rawOutput, MAX_OUTPUT_BYTES);
```

### Step 4: Run tests to verify they pass

Run: `pnpm --filter @sentinel/executor test -- bash.test`
Expected: PASS

### Step 5: Commit

```bash
git add packages/executor/src/tools/bash.ts packages/executor/src/tools/bash.test.ts
git commit -m "feat(executor): cap bash output at 50KB to prevent memory exhaustion"
```

---

## Task 6: Constant-Time Token Comparison

**Files:**
- Create: `packages/executor/src/auth.ts`
- Test: `packages/executor/src/auth.test.ts`

### Step 1: Write failing tests

Create `packages/executor/src/auth.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { timingSafeCompare } from "./auth.js";

describe("constant-time token comparison", () => {
  it("returns true for matching tokens", () => {
    expect(timingSafeCompare("secret-token-123", "secret-token-123")).toBe(true);
  });

  it("returns false for non-matching tokens", () => {
    expect(timingSafeCompare("secret-token-123", "wrong-token-456")).toBe(false);
  });

  it("returns false for different lengths", () => {
    expect(timingSafeCompare("short", "longer-string")).toBe(false);
  });

  it("returns false for empty vs non-empty", () => {
    expect(timingSafeCompare("", "non-empty")).toBe(false);
  });
});
```

### Step 2: Run tests to verify they fail

Run: `pnpm --filter @sentinel/executor test -- auth.test`
Expected: FAIL — module doesn't exist

### Step 3: Implement constant-time comparison

Create `packages/executor/src/auth.ts`:

```typescript
import { timingSafeEqual } from "node:crypto";

export function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
```

### Step 4: Run tests to verify they pass

Run: `pnpm --filter @sentinel/executor test -- auth.test`
Expected: PASS

### Step 5: Commit

```bash
git add packages/executor/src/auth.ts packages/executor/src/auth.test.ts
git commit -m "feat(executor): add constant-time token comparison (timing-attack resistant)"
```

---

## Task 7: Request UUID Middleware

**Files:**
- Modify: `packages/executor/src/server.ts`
- Test: add to existing server tests or create `packages/executor/src/server.test.ts`

### Step 1: Write failing test

```typescript
describe("Request UUID middleware", () => {
  it("adds x-request-id header to all responses", async () => {
    const res = await app.request("/health");
    const requestId = res.headers.get("x-request-id");
    expect(requestId).toBeDefined();
    expect(requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it("returns unique IDs per request", async () => {
    const res1 = await app.request("/health");
    const res2 = await app.request("/health");
    expect(res1.headers.get("x-request-id")).not.toBe(res2.headers.get("x-request-id"));
  });
});
```

### Step 2: Run tests to verify they fail

Run: `pnpm --filter @sentinel/executor test -- server.test`
Expected: FAIL — no x-request-id header

### Step 3: Add UUID middleware to server.ts

In `packages/executor/src/server.ts`, add middleware before route definitions in `createApp()`:

```typescript
// Request UUID middleware — structured correlation IDs
app.use("*", async (c, next) => {
  const requestId = crypto.randomUUID();
  c.set("requestId", requestId);
  await next();
  c.header("x-request-id", requestId);
});
```

### Step 4: Run tests to verify they pass

Run: `pnpm --filter @sentinel/executor test -- server.test`
Expected: PASS

### Step 5: Commit

```bash
git add packages/executor/src/server.ts packages/executor/src/server.test.ts
git commit -m "feat(executor): add request UUID middleware for structured correlation"
```

---

## Task 8: Wire New Stages into Router Pipeline

**Files:**
- Modify: `packages/executor/src/router.ts`
- Modify: `packages/executor/src/server.ts` (inject dependencies)
- Modify: `packages/executor/src/llm-proxy.ts` (add SSRF check)

### Step 1: Update router.ts to accept new dependencies

Modify `handleExecute` signature to accept `LoopGuard` and `RateLimiter`:

```typescript
import { LoopGuard, RateLimiter } from "@sentinel/policy";

export async function handleExecute(
  rawManifest: unknown,
  config: SentinelConfig,
  auditLogger: AuditLogger,
  registry: ToolRegistry,
  confirmFn: ConfirmFn,
  loopGuard?: LoopGuard,
  rateLimiter?: RateLimiter,
): Promise<ToolResult> {
```

Insert rate limit check after manifest validation, before classification:

```typescript
// Rate limit check
if (rateLimiter) {
  const rateResult = rateLimiter.check(manifest.agentId);
  if (!rateResult.allowed) {
    return {
      manifestId: manifest.id,
      success: false,
      error: `Rate limited. Retry after ${rateResult.retryAfterMs}ms`,
      duration_ms: 0,
    };
  }
}

// Loop guard check
if (loopGuard) {
  const loopResult = loopGuard.check(manifest.agentId, manifest.tool, manifest.parameters);
  if (loopResult.action === "block") {
    auditLogger.log({ ...auditBase, result: "blocked_by_policy", duration_ms: 0 });
    return {
      manifestId: manifest.id,
      success: false,
      error: loopResult.reason ?? "Loop detected",
      duration_ms: 0,
    };
  }
}
```

Note: `auditBase` is computed before classification, so you need to move the rate limit/loop guard checks to after `auditBase` is computed but before classification, OR compute a minimal audit base for the block case.

### Step 2: Update server.ts to instantiate and inject

In `createApp()`:
```typescript
import { LoopGuard, RateLimiter } from "@sentinel/policy";

// Inside createApp:
const loopGuard = new LoopGuard();
const rateLimiter = new RateLimiter({ period: 60_000, limit: 60, burst: 10 });

// Update the handleExecute call:
const result = await handleExecute(body, config, auditLogger, registry, confirmFn, loopGuard, rateLimiter);
```

### Step 3: Add SSRF check to LLM proxy

In `packages/executor/src/llm-proxy.ts`, add before the `fetch()` call:

```typescript
import { validateUrlNotPrivate } from "./ssrf-guard.js";

// Before the fetch() call, after building targetUrl:
try {
  await validateUrlNotPrivate(targetUrl);
} catch {
  return c.json({ error: "SSRF blocked" }, 403);
}
```

Also add SSRF check for the `x-llm-host` header — the ALLOWED_LLM_HOSTS check already handles this, but the SSRF guard adds DNS-level validation as defense-in-depth.

### Step 4: Run full test suite

Run: `pnpm test`
Expected: All existing tests pass

### Step 5: Commit

```bash
git add packages/executor/src/router.ts packages/executor/src/server.ts packages/executor/src/llm-proxy.ts
git commit -m "feat(executor): wire rate limiter, loop guard, and SSRF check into pipeline"
```

---

## Task 9: Security Invariant Tests 7-12

**Files:**
- Modify: `packages/executor/src/security-invariants.test.ts`

### Step 1: Write all 6 invariant tests

Add to `packages/executor/src/security-invariants.test.ts`:

```typescript
describe("Security Invariant #7: Merkle chain tamper-evident", () => {
  it("modified audit row detected by verifyChain", async () => {
    // Execute 3 tool calls to build chain
    await postExecute(app, makeManifest({ tool: "bash", parameters: { command: "echo 1" } }));
    await postExecute(app, makeManifest({ tool: "bash", parameters: { command: "echo 2" } }));
    await postExecute(app, makeManifest({ tool: "bash", parameters: { command: "echo 3" } }));

    // Tamper with middle entry
    const db = (auditLogger as any).db;
    db.prepare("UPDATE audit_log SET tool = 'TAMPERED' WHERE rowid = 2").run();

    const result = auditLogger.verifyChain();
    expect(result.valid).toBe(false);
    expect(result.brokenAtIndex).toBe(1);
  });
});

describe("Security Invariant #8: SSRF blocked", () => {
  it("LLM proxy rejects private IP targets", async () => {
    const res = await app.request("/proxy/llm/v1/test", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-llm-host": "127.0.0.1",
      },
      body: JSON.stringify({ prompt: "test" }),
    });
    expect(res.status).toBe(403);
  });
});

describe("Security Invariant #9: Per-agent rate limiting", () => {
  it("burst exceeding rate gets rejected", async () => {
    const results: number[] = [];
    // Send burst of requests
    for (let i = 0; i < 15; i++) {
      const res = await postExecute(app, makeManifest({
        tool: "bash",
        parameters: { command: `echo ${i}` },
      }));
      results.push(res.status);
    }
    // At least some should be rate-limited (422 with rate limit error)
    const limited = results.filter((r) => r === 422);
    expect(limited.length).toBeGreaterThan(0);
  });
});

describe("Security Invariant #10: PII scrubbed from outbound", () => {
  it("SSN in tool output is redacted", async () => {
    const manifest = makeManifest({
      tool: "bash",
      parameters: { command: "echo 'SSN: 123-45-6789'" },
    });
    const res = await postExecute(app, manifest);
    const result = (await res.json()) as ToolResult;
    expect(result.output).not.toContain("123-45-6789");
    expect(result.output).toContain("[PII_REDACTED]");
  });
});

describe("Security Invariant #11: Loop guard blocks storms", () => {
  it(">N identical calls are blocked", async () => {
    const manifests = Array.from({ length: 12 }, () =>
      makeManifest({ tool: "bash", parameters: { command: "echo same" } })
    );

    let blocked = false;
    for (const m of manifests) {
      const res = await postExecute(app, m);
      const result = (await res.json()) as ToolResult;
      if (!result.success && result.error?.includes("Loop")) {
        blocked = true;
        break;
      }
    }
    expect(blocked).toBe(true);
  });
});

describe("Security Invariant #12: Per-agent path whitelist", () => {
  it("agent cannot read outside allowedRoots", async () => {
    const manifest = makeManifest({
      tool: "read_file",
      parameters: { path: "/etc/passwd" },
    });
    const res = await postExecute(app, manifest);
    const result = (await res.json()) as ToolResult;
    expect(result.success).toBe(false);
    expect(result.error).toContain("denied");
  });
});
```

### Step 2: Run tests

Run: `pnpm --filter @sentinel/executor test -- security-invariants`
Expected: PASS (all 12 invariants)

### Step 3: Commit

```bash
git add packages/executor/src/security-invariants.test.ts
git commit -m "test: add invariant tests 7-12 (Merkle, SSRF, rate limit, PII, loop guard, path whitelist)"
```

---

## Task 10: Claude-mem Setup + Hardening

**This is the largest task (3 days). Break into sub-tasks.**

**Files:**
- Create: `sentinel/mem-hardening/validation.ts`
- Create: `sentinel/mem-hardening/validation.test.ts`
- Create: `sentinel/mem-hardening/size-caps.ts`
- Create: `sentinel/mem-hardening/size-caps.test.ts`
- Create: `sentinel/mem-hardening/index.ts`

**Sub-task 10a: Zod validation schemas for MCP tool inputs**

Write Zod schemas validating the 4 claude-mem MCP tool inputs:
- `search` — `{ query: string, limit?: number }`
- `timeline` — `{ start?: string, end?: string, limit?: number }`
- `get_observations` — `{ entityId: string }`
- `__IMPORTANT` — `{ content: string, tags?: string[] }`

Each gets a test verifying valid input passes and invalid input fails.

**Sub-task 10b: Pre-write credential scan**

Before any observation write, scan content against `CREDENTIAL_PATTERNS` from `@sentinel/types`. Reject entries containing credential patterns. Test: content with `sk-ant-...` is rejected.

**Sub-task 10c: Size caps**

- Per-observation: 10KB max (`Buffer.byteLength(content) <= 10240`)
- Total DB: 100MB max (check `PRAGMA page_count * page_size` before write)
- Test: 15KB observation is rejected; observation within 10KB passes.

**Sub-task 10d: Blocked categories**

Drop observations tagged with blocked categories: `credential`, `secret`, `password`, `token`, `api_key`. Test: observation tagged `credential` is silently dropped.

**Sub-task 10e: `<private>` tag enforcement**

Validate that `<private>` tags are stripped before storage. Log warning if raw tags reach storage layer. Test: content with `<private>foo</private>` has tags stripped.

**Each sub-task follows TDD: test → implement → commit.**

---

## Task 11: Rampart Evaluation

**Files:**
- Create: `docs/evaluations/rampart-evaluation.md`

**Research task (no code):**

1. Install Rampart: `go install github.com/peg/rampart@latest`
2. Write equivalent policies in YAML for Sentinel's classification rules
3. Test Rampart with Claude Code hooks
4. Document: overlap analysis, adoption recommendation, performance comparison
5. Decision: complement (defense-in-depth) or Phase 2.5 shortcut (replace custom hooks)

---

## Task Order & Dependencies

```
Independent (can parallelize):
├── Task 1: Merkle hash-chain
├── Task 2: SSRF guard
├── Task 3: Loop guard
├── Task 4: GCRA rate limiter
├── Task 5: Output truncation
├── Task 6: Constant-time comparison
├── Task 7: Request UUID middleware
└── Task 11: Rampart evaluation (research)

Sequential:
├── Task 8: Wire into pipeline (depends on 1-4)
├── Task 9: Invariant tests (depends on 8)
└── Task 10: claude-mem hardening (independent but large)
```

**Recommended execution:** Parallelize Tasks 1-7 via subagents, then Task 8-9 sequentially, then Task 10 in sub-batches.

---

## Verification Checklist (Post-Phase 1)

- [ ] `pnpm test` — all tests pass (335+ existing + ~40 new)
- [ ] `pnpm typecheck` — no type errors
- [ ] `pnpm lint` — no lint errors
- [ ] Tamper audit row → `verifyChain()` detects break
- [ ] LLM proxy to `127.0.0.1` → SSRF rejected
- [ ] 12 identical calls → loop guard blocks
- [ ] Burst of 15 rapid requests → rate limiter returns 429
- [ ] SSN in tool output → `[PII_REDACTED]`
- [ ] Bash output >50KB → truncated with `[TRUNCATED]`
- [ ] All 12 invariant tests pass
- [ ] claude-mem: oversized observation rejected, credential in memory blocked
- [ ] Rampart evaluation documented
- [ ] OWASP gate: `docs/owasp-reviews/phase-1.md` written
