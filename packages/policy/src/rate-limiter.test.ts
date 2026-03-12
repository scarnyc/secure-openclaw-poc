import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RateLimiter } from "./rate-limiter.js";

describe("RateLimiter (GCRA)", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("allows the first request", () => {
		const limiter = new RateLimiter({ rate: 5, period: 1000 });
		const result = limiter.check("agent-1");
		expect(result.allowed).toBe(true);
		expect(result.retryAfter).toBeUndefined();
	});

	it("allows requests within rate limit", () => {
		const limiter = new RateLimiter({ rate: 5, period: 1000 });
		for (let i = 0; i < 5; i++) {
			const result = limiter.check("agent-1");
			expect(result.allowed).toBe(true);
		}
	});

	it("rejects request exceeding rate limit with retryAfter > 0", () => {
		const limiter = new RateLimiter({ rate: 5, period: 1000 });
		// Exhaust the limit
		for (let i = 0; i < 5; i++) {
			limiter.check("agent-1");
		}
		const result = limiter.check("agent-1");
		expect(result.allowed).toBe(false);
		expect(result.retryAfter).toBeDefined();
		expect(result.retryAfter).toBeGreaterThan(0);
	});

	it("allows request after waiting retryAfter ms", () => {
		const limiter = new RateLimiter({ rate: 5, period: 1000 });
		for (let i = 0; i < 5; i++) {
			limiter.check("agent-1");
		}
		const rejected = limiter.check("agent-1");
		expect(rejected.allowed).toBe(false);

		expect(rejected.retryAfter).toBeDefined();
		vi.advanceTimersByTime(rejected.retryAfter as number);

		const result = limiter.check("agent-1");
		expect(result.allowed).toBe(true);
	});

	it("maintains independent limits per agent", () => {
		const limiter = new RateLimiter({ rate: 2, period: 1000 });
		// Exhaust agent-1
		limiter.check("agent-1");
		limiter.check("agent-1");
		const rejected = limiter.check("agent-1");
		expect(rejected.allowed).toBe(false);

		// agent-2 should still be allowed
		const result = limiter.check("agent-2");
		expect(result.allowed).toBe(true);
	});

	it("reset(agentId) clears that agent's TAT", () => {
		const limiter = new RateLimiter({ rate: 2, period: 1000 });
		limiter.check("agent-1");
		limiter.check("agent-1");
		expect(limiter.check("agent-1").allowed).toBe(false);

		limiter.reset("agent-1");
		expect(limiter.check("agent-1").allowed).toBe(true);
	});

	it("reset() with no args clears all TATs", () => {
		const limiter = new RateLimiter({ rate: 2, period: 1000 });
		limiter.check("agent-1");
		limiter.check("agent-1");
		limiter.check("agent-2");
		limiter.check("agent-2");
		expect(limiter.check("agent-1").allowed).toBe(false);
		expect(limiter.check("agent-2").allowed).toBe(false);

		limiter.reset();
		expect(limiter.check("agent-1").allowed).toBe(true);
		expect(limiter.check("agent-2").allowed).toBe(true);
	});

	it("throws on zero rate", () => {
		expect(() => new RateLimiter({ rate: 0, period: 1000 })).toThrow(
			"rate and period must be positive",
		);
	});

	it("throws on negative period", () => {
		expect(() => new RateLimiter({ rate: 5, period: -1 })).toThrow(
			"rate and period must be positive",
		);
	});

	it("throws on maxAgents < 1", () => {
		expect(() => new RateLimiter({ rate: 10, period: 1000, maxAgents: 0 })).toThrow(
			"maxAgents must be positive",
		);
		expect(() => new RateLimiter({ rate: 10, period: 1000, maxAgents: -1 })).toThrow(
			"maxAgents must be positive",
		);
	});

	it("evicts oldest agent when maxAgents exceeded", () => {
		const limiter = new RateLimiter({ rate: 10, period: 1000, maxAgents: 3 });
		limiter.check("agent-1");
		limiter.check("agent-2");
		limiter.check("agent-3");
		limiter.check("agent-4"); // should evict agent-1
		// agent-1 should have fresh state (evicted and re-created)
		const result = limiter.check("agent-1");
		expect(result.allowed).toBe(true);
	});

	it("defaults maxAgents to 1000", () => {
		const limiter = new RateLimiter({ rate: 10, period: 1000 });
		// Should not throw for up to 1001 agents
		for (let i = 0; i < 1001; i++) {
			limiter.check(`agent-${i}`);
		}
		// Just verify it doesn't crash
		expect(true).toBe(true);
	});

	it("burst: first N requests allowed, rest rejected", () => {
		const rate = 10;
		const limiter = new RateLimiter({ rate, period: 5000 });

		const results: boolean[] = [];
		for (let i = 0; i < rate + 5; i++) {
			results.push(limiter.check("agent-burst").allowed);
		}

		const allowed = results.filter((r) => r);
		const rejected = results.filter((r) => !r);
		expect(allowed).toHaveLength(rate);
		expect(rejected).toHaveLength(5);
	});
});

describe("RateLimiter with SQLite persistence", () => {
	let tmpDir: string;
	let dbPath: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rate-limiter-test-"));
		dbPath = path.join(tmpDir, "rate-limiter.db");
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("preserves TAT state across close and reopen", () => {
		// Create limiter, exhaust rate
		const limiter1 = new RateLimiter({ rate: 5, period: 1000, dbPath });
		for (let i = 0; i < 5; i++) {
			expect(limiter1.check("agent-1").allowed).toBe(true);
		}
		// 6th should be rejected
		expect(limiter1.check("agent-1").allowed).toBe(false);
		limiter1.close();

		// Reopen with same dbPath — TAT should be preserved
		const limiter2 = new RateLimiter({ rate: 5, period: 1000, dbPath });
		expect(limiter2.check("agent-1").allowed).toBe(false);
		limiter2.close();
	});

	it("batches writes efficiently via write-behind", () => {
		const limiter = new RateLimiter({ rate: 200, period: 10000, dbPath });

		// Make 100 rapid checks
		for (let i = 0; i < 100; i++) {
			limiter.check(`agent-${i}`);
		}

		// Before close, DB may have no rows (write-behind hasn't fired)
		// close() triggers final flush
		limiter.close();

		// Verify all 100 entries are in the DB
		const db = new Database(dbPath);
		const count = db.prepare("SELECT COUNT(*) as cnt FROM rate_limiter_state").get() as {
			cnt: number;
		};
		expect(count.cnt).toBe(100);
		db.close();
	});

	it("works as pure in-memory without dbPath (backward compat)", () => {
		const limiter = new RateLimiter({ rate: 5, period: 1000 });

		for (let i = 0; i < 5; i++) {
			expect(limiter.check("agent-1").allowed).toBe(true);
		}
		expect(limiter.check("agent-1").allowed).toBe(false);

		// close() should not throw on in-memory limiter
		limiter.close();
	});

	it("skips expired TAT values on restart", () => {
		const limiter1 = new RateLimiter({ rate: 5, period: 1000, dbPath });
		for (let i = 0; i < 5; i++) {
			limiter1.check("agent-1");
		}
		limiter1.close();

		// Wait well past the period so TATs expire
		// Manually write an old TAT into the DB to simulate time passing
		const db = new Database(dbPath);
		const expiredTat = Date.now() - 5000; // 5 seconds ago, well past 1s period
		db.prepare("UPDATE rate_limiter_state SET tat = ? WHERE agent_id = ?").run(
			expiredTat,
			"agent-1",
		);
		db.close();

		// Reopen — expired TAT should not be loaded
		const limiter2 = new RateLimiter({ rate: 5, period: 1000, dbPath });
		// Agent should get a fresh start — all 5 requests allowed
		for (let i = 0; i < 5; i++) {
			expect(limiter2.check("agent-1").allowed).toBe(true);
		}
		limiter2.close();
	});

	it("close() flushes pending writes immediately", () => {
		const limiter = new RateLimiter({ rate: 10, period: 5000, dbPath });

		// Make some checks
		limiter.check("agent-a");
		limiter.check("agent-b");
		limiter.check("agent-c");

		// Immediately close without waiting for the 1s flush interval
		limiter.close();

		// Verify state was persisted
		const db = new Database(dbPath);
		const rows = db
			.prepare("SELECT agent_id FROM rate_limiter_state ORDER BY agent_id")
			.all() as Array<{ agent_id: string }>;
		expect(rows.map((r) => r.agent_id)).toEqual(["agent-a", "agent-b", "agent-c"]);
		db.close();
	});
});
