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
