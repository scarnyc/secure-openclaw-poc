# Design: Sentinel Memory Store

**Date**: 2026-03-09
**Phase**: Completes Phase 1 (invariants #4, #5) + lays foundation for Phase 2/2.5
**Decision**: Build minimal memory layer inside Sentinel; do NOT fork claude-mem

## Context

### Why Not Claude-Mem

Claude-mem (github.com/thedotmack/claude-mem) is a 605-file, AGPL-licensed plugin with its own Express server, React viewer, Bun runtime dependency, and SDK agent subprocess for agentic observation compression. Security audit revealed:

- No credential scrubbing on stored observations
- Plaintext API key storage in `~/.claude-mem/.env`
- No authentication on HTTP API (localhost:37777)
- No audit integrity mechanism (no hash chain)
- No memory size caps
- AGPL-3.0 license complicates distribution

The security hardening required is so extensive that building from scratch inside Sentinel's trust boundary is less work and more secure than forking and auditing 605 files.

### What We Extract (Ideas, Not Code)

From claude-mem:
- FTS5 virtual table for full-text search
- Content deduplication via SHA-256
- Progressive disclosure retrieval (compact → detailed)
- Observation schema structure (title, content, concepts, files)

From Nat Eliason's PARA-based 3-layer system:
- **Knowledge Base** — structured long-term memory (projects, areas, resources)
- **Daily Log** — morning cron consolidates previous day's sessions
- **Tacit Knowledge** — operational rules, read-only for agents

### What We Build

~500 lines of new code in `sentinel/mem-hardening/`, following established patterns from `@sentinel/audit` (WAL mode, prepared statements, Zod validation, Merkle-compatible design).


## Architecture

### Trust Model

```
┌──────────────────┐     ┌──────────────────────────┐
│   Claude Code     │     │   OpenClaw Agent          │
│   (trusted)       │     │   (untrusted, Docker)     │
│                   │     │                            │
│  Direct SQLite    │     │  HTTP only:                │
│  read/write       │     │  POST /memory/observe      │
│                   │     │  GET  /memory/query         │
└────────┬──────────┘     └──────────┬─────────────────┘
         │                           │
         │                  ┌────────▼─────────┐
         │                  │  Executor         │
         │                  │  (trusted)        │
         │                  │                   │
         │                  │  • Zod validate   │
         │                  │  • Credential scrub│
         │                  │  • PII scrub       │
         │                  │  • Size cap check  │
         │                  │  • Write to SQLite │
         │                  └────────┬──────────┘
         │                           │
         ▼                           ▼
    ┌────────────────────────────────────┐
    │        memory.db (SQLite)          │
    │        WAL mode, FTS5              │
    │                                    │
    │  namespace: "developer" | "agent"  │
    │  trust_level per row               │
    └────────────────────────────────────┘
```

- **Claude Code** reads/writes directly (trusted — it's the operator's tool)
- **OpenClaw agents** read/write through executor validation pipeline (untrusted)
- Both share the same SQLite database, namespaced by `source` and `project`
- `trust_level` column distinguishes provenance: writes from Claude Code are `developer`; writes from agents are `agent` (validated by executor)


## SQLite Schema

### Core Tables

```sql
-- Observations: individual captured events (tool calls, learnings, errors)
CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY,                          -- UUID
  project TEXT NOT NULL,                        -- git repo root or project identifier
  session_id TEXT NOT NULL,                     -- session that created this
  agent_id TEXT NOT NULL DEFAULT 'claude-code',  -- 'claude-code' or agent ID
  source TEXT NOT NULL CHECK(source IN ('developer', 'agent')),  -- trust level
  type TEXT NOT NULL CHECK(type IN ('tool_call', 'learning', 'error', 'decision', 'context')),
  title TEXT NOT NULL,                          -- short summary (max 200 chars)
  content TEXT NOT NULL,                        -- full observation body
  concepts TEXT NOT NULL DEFAULT '[]',          -- JSON array of concept tags
  files_involved TEXT NOT NULL DEFAULT '[]',    -- JSON array of file paths
  content_hash TEXT NOT NULL,                   -- SHA-256 for deduplication
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_obs_project ON observations(project);
CREATE INDEX idx_obs_session ON observations(session_id);
CREATE INDEX idx_obs_agent ON observations(agent_id);
CREATE INDEX idx_obs_created ON observations(created_at);
CREATE INDEX idx_obs_hash ON observations(content_hash);

-- FTS5 virtual table for full-text search over observations
CREATE VIRTUAL TABLE IF NOT EXISTS observations_fts USING fts5(
  title,
  content,
  concepts,
  content_id UNINDEXED,       -- reference to observations.id
  tokenize='porter unicode61'
);

-- Summaries: compressed daily/session digests
CREATE TABLE IF NOT EXISTS summaries (
  id TEXT PRIMARY KEY,                          -- UUID
  project TEXT NOT NULL,
  source TEXT NOT NULL CHECK(source IN ('developer', 'agent')),
  scope TEXT NOT NULL CHECK(scope IN ('session', 'daily', 'weekly')),
  period_start TEXT NOT NULL,                   -- ISO timestamp
  period_end TEXT NOT NULL,                     -- ISO timestamp
  title TEXT NOT NULL,
  investigated TEXT NOT NULL DEFAULT '[]',      -- JSON array
  learned TEXT NOT NULL DEFAULT '[]',           -- JSON array
  completed TEXT NOT NULL DEFAULT '[]',         -- JSON array
  next_steps TEXT NOT NULL DEFAULT '[]',        -- JSON array
  observation_ids TEXT NOT NULL DEFAULT '[]',   -- JSON array of source observation IDs
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_sum_project ON summaries(project);
CREATE INDEX idx_sum_period ON summaries(period_start, period_end);
CREATE INDEX idx_sum_scope ON summaries(scope);

-- Storage tracking for global size cap enforcement
CREATE TABLE IF NOT EXISTS storage_stats (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### Size Constraints (Invariant #4)

| Constraint | Limit | Enforcement |
|-----------|-------|-------------|
| Single observation `content` | 10 KB | Zod `.max(10240)` + pre-write check |
| Single observation `title` | 200 chars | Zod `.max(200)` |
| Single `concepts` array | 50 items | Zod `.max(50)` |
| Single `files_involved` array | 100 items | Zod `.max(100)` |
| Global database size | 100 MB | Check `storage_stats.total_bytes` before write; reject with `MEMORY_QUOTA_EXCEEDED` |
| Single summary body fields | 5 KB each | Zod `.max(5120)` per array field |


## Zod Schemas

```typescript
// sentinel/mem-hardening/schema.ts

import { z } from "zod";

export const ObservationTypeSchema = z.enum([
  "tool_call", "learning", "error", "decision", "context",
]);

export const SourceSchema = z.enum(["developer", "agent"]);

export const ScopeSchema = z.enum(["session", "daily", "weekly"]);

export const CreateObservationSchema = z.object({
  project: z.string().min(1).max(500),
  sessionId: z.string().min(1).max(200),
  agentId: z.string().min(1).max(200).default("claude-code"),
  source: SourceSchema,
  type: ObservationTypeSchema,
  title: z.string().min(1).max(200),
  content: z.string().min(1).max(10240),           // 10 KB cap
  concepts: z.array(z.string().max(100)).max(50).default([]),
  filesInvolved: z.array(z.string().max(500)).max(100).default([]),
});

export type CreateObservation = z.infer<typeof CreateObservationSchema>;

export const ObservationSchema = CreateObservationSchema.extend({
  id: z.string().uuid(),
  contentHash: z.string().length(64),
  createdAt: z.string().datetime(),
});

export type Observation = z.infer<typeof ObservationSchema>;

export const SearchQuerySchema = z.object({
  query: z.string().max(1000).optional(),            // FTS5 search text
  project: z.string().max(500).optional(),
  agentId: z.string().max(200).optional(),
  type: ObservationTypeSchema.optional(),
  source: SourceSchema.optional(),
  fromDate: z.string().datetime().optional(),
  toDate: z.string().datetime().optional(),
  limit: z.number().int().min(1).max(100).default(20),
  offset: z.number().int().min(0).default(0),
});

export type SearchQuery = z.infer<typeof SearchQuerySchema>;

export const CreateSummarySchema = z.object({
  project: z.string().min(1).max(500),
  source: SourceSchema,
  scope: ScopeSchema,
  periodStart: z.string().datetime(),
  periodEnd: z.string().datetime(),
  title: z.string().min(1).max(200),
  investigated: z.array(z.string().max(5120)).max(20).default([]),
  learned: z.array(z.string().max(5120)).max(20).default([]),
  completed: z.array(z.string().max(5120)).max(20).default([]),
  nextSteps: z.array(z.string().max(5120)).max(20).default([]),
  observationIds: z.array(z.string().uuid()).default([]),
});

export type CreateSummary = z.infer<typeof CreateSummarySchema>;
```


## Validator

```typescript
// sentinel/mem-hardening/validator.ts (pseudocode)

import { redactAll } from "@sentinel/types";

export interface ValidationResult {
  valid: true; sanitized: CreateObservation;
} | {
  valid: false; reason: string; code: string;
}

export function validateObservation(input: unknown): ValidationResult {
  // 1. Zod parse (schema validation + size caps)
  const parsed = CreateObservationSchema.safeParse(input);
  if (!parsed.success) return { valid: false, reason: parsed.error.message, code: "SCHEMA_INVALID" };

  // 2. Credential + PII scan on content fields
  const sanitizedContent = redactAll(parsed.data.content);
  const sanitizedTitle = redactAll(parsed.data.title);

  // 3. Check if content was ONLY credentials (fully redacted → reject)
  if (sanitizedContent.trim() === "[REDACTED]" || sanitizedContent.trim() === "[PII_REDACTED]") {
    return { valid: false, reason: "Observation contains only sensitive data", code: "CONTENT_ONLY_SENSITIVE" };
  }

  // 4. Global quota check (delegated to store)
  // Done at write time in store.ts, not here

  return {
    valid: true,
    sanitized: { ...parsed.data, content: sanitizedContent, title: sanitizedTitle },
  };
}
```


## Memory Store

```typescript
// sentinel/mem-hardening/store.ts (key methods)

export class MemoryStore {
  private db: Database.Database;
  private insertObs: Database.Statement;
  private insertFts: Database.Statement;
  private searchFts: Database.Statement;
  // ... prepared statements

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.initSchema();
    this.prepareStatements();
  }

  /**
   * Write an observation (after validation + scrubbing).
   * Returns the observation ID, or throws if quota exceeded or duplicate.
   */
  observe(input: CreateObservation): string {
    // Compute content hash for dedup
    const hash = createHash("sha256").update(input.content).digest("hex");

    // Check 30-second dedup window
    const recent = this.findRecentByHash(hash, 30);
    if (recent) return recent.id;  // idempotent — return existing

    // Check global quota
    const totalBytes = this.getStorageBytes();
    const newBytes = Buffer.byteLength(input.content, "utf-8");
    if (totalBytes + newBytes > MAX_TOTAL_BYTES) {
      throw new MemoryQuotaError("Global memory quota exceeded (100 MB)");
    }

    // Insert in transaction
    const id = crypto.randomUUID();
    this.db.transaction(() => {
      this.insertObs.run(id, input.project, input.sessionId, ...);
      this.insertFts.run(input.title, input.content, JSON.stringify(input.concepts), id);
      this.updateStorageStats(totalBytes + newBytes);
    })();

    return id;
  }

  /**
   * Search observations via FTS5 + filters.
   * Returns scrubbed results (credentials/PII already stripped at write time).
   */
  search(query: SearchQuery): Observation[] {
    if (query.query) {
      // FTS5 match query with rank ordering
      return this.searchFts(query);
    }
    // Filter-only query (project, type, date range)
    return this.filterQuery(query);
  }

  /**
   * Get context for session start (progressive disclosure).
   * Returns compact index of recent + relevant observations.
   */
  getContextForSession(project: string, agentId: string): string {
    // Layer 1: Recent summaries (last 3 daily summaries)
    const summaries = this.getRecentSummaries(project, 3);
    // Layer 2: Recent observations from this agent (last 20)
    const recent = this.getRecentByAgent(project, agentId, 20);
    // Format as markdown context block
    return formatContextBlock(summaries, recent);
  }

  /**
   * Get total storage bytes for quota enforcement.
   */
  getStorageBytes(): number { ... }

  close(): void { this.db.close(); }
}
```


## Consolidation: Dual-Trigger Design

Two triggers, complementary roles:

### Session-End Hook (Capture)

**When**: Fires at end of every Claude Code session (existing `/diary` chain) and at OpenClaw agent session end.

**What it does**:
1. Collect all observations from this session
2. Generate a structured session summary (investigated, learned, completed, next_steps)
3. Write summary to `summaries` table with `scope: 'session'`
4. No observation pruning — raw observations preserved for morning consolidation

**For Claude Code**: Integrates with existing session maintenance chain. The `/diary` skill writes to `memory/` markdown AND to the SQLite store. No behavior change for the developer — the diary still appears in markdown, but is now also searchable via FTS5.

**For OpenClaw**: Executor triggers summary generation when agent session ends (detected via heartbeat timeout or explicit `/session/end` call).

### Morning Cron (Synthesize)

**When**: Runs daily at 8:00 AM local time (configurable via `SENTINEL_CONSOLIDATION_HOUR`).

**What it does**:
1. Query all session summaries from the previous day (`scope: 'session'`, `created_at` within yesterday)
2. Group by project
3. For each project, generate a daily digest summary (`scope: 'daily'`)
   - Cross-session patterns: what topics appeared in multiple sessions?
   - Key learnings and decisions across all sessions
   - Outstanding next_steps that weren't completed
4. Archive raw observations older than `SENTINEL_OBS_RETENTION_DAYS` (default: 30)
   - Observations referenced by summaries are preserved
   - Orphaned observations beyond retention period are deleted
   - Storage stats updated after pruning
5. Write daily summary to `summaries` table with `scope: 'daily'`

**Weekly rollup** (Sundays): Same pattern but compresses the week's daily summaries into a `scope: 'weekly'` summary. This creates the progressive disclosure pyramid:

```
weekly summaries (compressed, long-lived)
  └── daily summaries (medium detail, 90-day retention)
       └── session summaries (detailed, 30-day retention)
            └── raw observations (full detail, 30-day retention with pruning)
```

### Cron Implementation

```typescript
// sentinel/mem-hardening/consolidator.ts

export interface ConsolidatorConfig {
  hour: number;                    // 0-23, default 7
  obsRetentionDays: number;        // default 30
  summaryRetentionDays: number;    // default 90
}

export class Consolidator {
  constructor(
    private store: MemoryStore,
    private config: ConsolidatorConfig,
  ) {}

  /**
   * Run daily consolidation for yesterday's sessions.
   * Idempotent: skips if daily summary already exists for the period.
   */
  async consolidateYesterday(): Promise<DailyConsolidation> {
    const yesterday = getYesterdayRange();  // { start: ISO, end: ISO }

    // Skip if already consolidated
    if (this.store.hasSummaryForPeriod("daily", yesterday)) return { skipped: true };

    // Get all session summaries from yesterday
    const sessions = this.store.getSummariesByPeriod("session", yesterday);

    // Group by project, generate daily digests
    const byProject = groupBy(sessions, s => s.project);
    const results: DailySummary[] = [];

    for (const [project, projectSessions] of Object.entries(byProject)) {
      const daily = this.synthesizeDailySummary(project, projectSessions);
      this.store.writeSummary(daily);
      results.push(daily);
    }

    // Prune old observations
    const pruned = this.store.pruneObservations(this.config.obsRetentionDays);

    return { skipped: false, summaries: results, prunedObservations: pruned };
  }

  /**
   * Run weekly rollup (call on Sunday mornings).
   */
  async consolidateWeek(): Promise<WeeklyConsolidation> { ... }

  /**
   * Synthesize daily summary from session summaries.
   * No LLM call — deterministic extraction + dedup.
   */
  private synthesizeDailySummary(
    project: string,
    sessions: Summary[],
  ): CreateSummary {
    // Merge investigated/learned/completed/next_steps across sessions
    // Deduplicate by content similarity (exact match + prefix match)
    // Identify cross-session patterns (concepts appearing 2+ times)
    return { ... };
  }
}
```

**Key design decision**: Daily consolidation is **deterministic, not agentic**. No LLM calls. It merges and deduplicates session summaries using string matching and concept overlap. This means:
- Zero API cost for consolidation
- Predictable, testable output
- No risk of hallucinated summaries
- Fast execution (pure SQLite queries + string ops)

If richer synthesis is needed later (Phase 2.5), an optional LLM pass can be added on top.


## Claude Code Integration

### FTS5 Cross-Session Search

Claude Code gains a new capability: searching across all past sessions.

**Integration point**: A new MCP tool or CLI command that queries the FTS5 index.

```
sentinel mem search "SSRF guard implementation"
sentinel mem search --project secure-openclaw --type learning --last 7d
sentinel mem recent --limit 10
```

Alternatively, exposed as an MCP tool so Claude Code can self-serve:

```typescript
// MCP tool: mem_search
{
  name: "mem_search",
  description: "Search past session observations and learnings",
  inputSchema: SearchQuerySchema,
  handler: (input) => store.search(input),
}
```

### Session Diary Integration

The existing `/diary` skill writes markdown to `memory/`. We add a parallel write to SQLite:

```
┌─────────────────────┐
│  /diary skill        │
│  (session end)       │
├──────────┬──────────┤
│ Write to │ Write to │
│ memory/  │ SQLite   │
│ *.md     │ store    │
│ (human-  │ (machine-│
│ readable)│ search-  │
│          │ able)    │
└──────────┴──────────┘
```

Markdown files remain the source of truth for human reading. SQLite is the search index. No behavioral change for the developer.


## Phase 2 Extension: Executor Endpoints

When OpenClaw agents are running (Phase 2), the executor exposes two new endpoints:

```
POST /memory/observe
  Body: CreateObservation (Zod validated)
  → validator.validateObservation() → store.observe()
  → Returns: { id: string } | { error: string, code: string }

GET /memory/query
  Query: SearchQuery (Zod validated)
  → store.search()
  → Returns: Observation[] (already scrubbed at write time)
```

These endpoints sit behind the existing auth middleware (Invariant #1) and rate limiter (Invariant #9). Agent writes are always `source: "agent"` — the executor sets this field, ignoring whatever the agent sends.


## Phase 2.5 Extension: Shared Memory

When both Claude Code and OpenClaw need shared context:

1. **Namespace isolation**: `source` column distinguishes `developer` vs `agent` writes
2. **Read access**: Both can read all observations (no read restriction)
3. **Write trust**: Agent writes are validated; developer writes bypass validation (trusted)
4. **Promotion**: Morning cron can flag high-quality agent learnings for developer review
   - Agent observations referenced by 3+ sessions → candidate for promotion
   - Developer confirms via CLI: `sentinel mem promote <observation-id>`
   - Promoted observations get `source: 'developer'` (trust upgrade)


## File Layout

```
sentinel/mem-hardening/
├── index.ts               # Barrel exports
├── schema.ts              # Zod schemas (observation, summary, search query)
├── store.ts               # MemoryStore class (SQLite + FTS5, CRUD, search)
├── validator.ts           # Pre-write validation (size caps, credential/PII scan)
├── context-builder.ts     # Session-start context injection (progressive disclosure)
├── consolidator.ts        # Morning cron + session-end summary generation
├── errors.ts              # MemoryQuotaError, DuplicateObservationError
└── __tests__/
    ├── invariant-4-size-caps.test.ts     # Invariant #4: oversized rejected
    ├── invariant-5-no-creds.test.ts      # Invariant #5: credentials blocked
    ├── store.test.ts                     # CRUD, FTS5 search, dedup, quota
    ├── consolidator.test.ts             # Daily/weekly consolidation, pruning
    └── context-builder.test.ts          # Progressive disclosure formatting
```

**Estimated LOC**: ~500 (implementation) + ~400 (tests) = ~900 total


## Security Invariant Tests

### Invariant #4: Memory Size Caps Enforced

```typescript
describe("Invariant #4: Memory size caps", () => {
  it("rejects observation exceeding 10KB content limit", () => {
    const bigContent = "x".repeat(10241);  // 10KB + 1 byte
    const result = validateObservation({ ...validObs, content: bigContent });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("SCHEMA_INVALID");
  });

  it("rejects write when global quota (100MB) exceeded", () => {
    // Seed store to just under 100MB
    // Attempt one more write
    expect(() => store.observe(obs)).toThrow(MemoryQuotaError);
  });

  it("truncates title exceeding 200 chars", () => {
    const result = validateObservation({ ...validObs, title: "x".repeat(201) });
    expect(result.valid).toBe(false);
  });
});
```

### Invariant #5: No Credential Storage in Memory

```typescript
describe("Invariant #5: No credentials in memory", () => {
  it("strips API key from observation content before storage", () => {
    const obs = { ...validObs, content: "Found key sk-ant-abc123xyz in config" };
    const result = validateObservation(obs);
    expect(result.valid).toBe(true);
    expect(result.sanitized.content).not.toContain("sk-ant-");
    expect(result.sanitized.content).toContain("[REDACTED]");
  });

  it("strips PII from observation content before storage", () => {
    const obs = { ...validObs, content: "User SSN is 123-45-6789" };
    const result = validateObservation(obs);
    expect(result.valid).toBe(true);
    expect(result.sanitized.content).toContain("[PII_REDACTED]");
  });

  it("rejects observation that is entirely credential data", () => {
    const obs = { ...validObs, content: "sk-ant-abc123xyz456" };
    const result = validateObservation(obs);
    expect(result.valid).toBe(false);
    expect(result.code).toBe("CONTENT_ONLY_SENSITIVE");
  });
});
```


## Dependencies

| Package | Already in Project? | Notes |
|---------|-------------------|-------|
| `better-sqlite3` | Yes (`@sentinel/audit`) | Shared native module |
| `zod` | Yes (`@sentinel/types`) | Schema validation |
| `@sentinel/types` | Yes | Import `redactAll` |
| `node:crypto` | Built-in | SHA-256 hashing, UUIDs |

**No new dependencies.** Everything needed is already in the monorepo.


## Acceptance Criteria

- [ ] `pnpm test` passes with invariant #4 tests (size caps enforced)
- [ ] `pnpm test` passes with invariant #5 tests (credentials blocked from memory)
- [ ] FTS5 search returns relevant results for keyword queries
- [ ] Content deduplication prevents identical observations within 30-second window
- [ ] Global quota enforcement rejects writes at 100MB
- [ ] Session summary generation produces valid `CreateSummary` from observations
- [ ] Morning consolidation is idempotent (running twice produces same result)
- [ ] Observation pruning respects retention period and preserves referenced observations
- [ ] `pnpm typecheck` passes
- [ ] `pnpm lint` passes
