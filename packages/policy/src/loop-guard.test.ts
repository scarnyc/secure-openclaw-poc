import { describe, expect, it, vi } from "vitest";
import { LoopGuard } from "./loop-guard.js";

describe("LoopGuard", () => {
	const agentId = "test-agent";
	const tool = "read_file";
	const params = { path: "/etc/hosts" };

	it("first call always returns allow", () => {
		const guard = new LoopGuard();
		const result = guard.check(agentId, tool, params);
		expect(result.action).toBe("allow");
		expect(result.duplicateCount).toBe(1);
	});

	it("2 identical calls within window → allow (below warn threshold)", () => {
		const guard = new LoopGuard();
		guard.check(agentId, tool, params);
		const result = guard.check(agentId, tool, params);
		expect(result.action).toBe("allow");
		expect(result.duplicateCount).toBe(2);
	});

	it("3 identical calls within window → warn (at warn threshold with default config)", () => {
		const guard = new LoopGuard();
		guard.check(agentId, tool, params);
		guard.check(agentId, tool, params);
		const result = guard.check(agentId, tool, params);
		expect(result.action).toBe("warn");
		expect(result.duplicateCount).toBe(3);
		expect(result.reason).toBeDefined();
		expect(result.reason).toContain("read_file");
	});

	it("5 identical calls within window → block (at block threshold with default config)", () => {
		const guard = new LoopGuard();
		for (let i = 0; i < 4; i++) {
			guard.check(agentId, tool, params);
		}
		const result = guard.check(agentId, tool, params);
		expect(result.action).toBe("block");
		expect(result.duplicateCount).toBe(5);
		expect(result.reason).toBeDefined();
		expect(result.reason).toContain("read_file");
	});

	it("different tool calls don't count as duplicates", () => {
		const guard = new LoopGuard();
		guard.check(agentId, "read_file", params);
		guard.check(agentId, "write_file", params);
		guard.check(agentId, "list_files", params);
		const result = guard.check(agentId, "read_file", params);
		expect(result.action).toBe("allow");
		expect(result.duplicateCount).toBe(2);
	});

	it("same tool but different params don't count as duplicates", () => {
		const guard = new LoopGuard();
		guard.check(agentId, tool, { path: "/etc/hosts" });
		guard.check(agentId, tool, { path: "/etc/passwd" });
		guard.check(agentId, tool, { path: "/etc/shadow" });
		const result = guard.check(agentId, tool, { path: "/etc/hosts" });
		expect(result.action).toBe("allow");
		expect(result.duplicateCount).toBe(2);
	});

	it("calls outside window don't count", () => {
		vi.useFakeTimers();
		const guard = new LoopGuard({ windowMs: 1000 });

		guard.check(agentId, tool, params);
		guard.check(agentId, tool, params);

		// Advance past the window
		vi.advanceTimersByTime(1500);

		const result = guard.check(agentId, tool, params);
		expect(result.action).toBe("allow");
		expect(result.duplicateCount).toBe(1);

		vi.useRealTimers();
	});

	it("reset(agentId) clears that agent's history", () => {
		const guard = new LoopGuard();
		guard.check(agentId, tool, params);
		guard.check(agentId, tool, params);
		guard.check(agentId, tool, params);

		guard.reset(agentId);

		const result = guard.check(agentId, tool, params);
		expect(result.action).toBe("allow");
		expect(result.duplicateCount).toBe(1);
	});

	it("reset() with no args clears all history", () => {
		const guard = new LoopGuard();
		guard.check("agent-1", tool, params);
		guard.check("agent-1", tool, params);
		guard.check("agent-1", tool, params);
		guard.check("agent-2", tool, params);
		guard.check("agent-2", tool, params);
		guard.check("agent-2", tool, params);

		guard.reset();

		const r1 = guard.check("agent-1", tool, params);
		const r2 = guard.check("agent-2", tool, params);
		expect(r1.action).toBe("allow");
		expect(r1.duplicateCount).toBe(1);
		expect(r2.action).toBe("allow");
		expect(r2.duplicateCount).toBe(1);
	});

	it("history is trimmed to maxHistorySize", () => {
		const guard = new LoopGuard({ maxHistorySize: 5, warnThreshold: 10, blockThreshold: 20 });

		// Add 5 different calls to fill history
		for (let i = 0; i < 5; i++) {
			guard.check(agentId, `tool-${i}`, {});
		}

		// Add 3 more — oldest entries should be evicted
		guard.check(agentId, "tool-new-1", {});
		guard.check(agentId, "tool-new-2", {});
		guard.check(agentId, "tool-new-3", {});

		// Now check tool-0 — it was evicted, so count should be 1 (fresh)
		const result = guard.check(agentId, "tool-0", {});
		expect(result.duplicateCount).toBe(1);
	});

	it("multiple agents tracked independently", () => {
		const guard = new LoopGuard();

		// Agent 1 hits warn threshold
		guard.check("agent-1", tool, params);
		guard.check("agent-1", tool, params);
		const r1 = guard.check("agent-1", tool, params);
		expect(r1.action).toBe("warn");

		// Agent 2 is still fresh
		const r2 = guard.check("agent-2", tool, params);
		expect(r2.action).toBe("allow");
		expect(r2.duplicateCount).toBe(1);
	});

	it("ping-pong pattern (alternating A, B, A, B) — each hash count stays low, no false block", () => {
		const guard = new LoopGuard();
		const paramsA = { path: "/a" };
		const paramsB = { path: "/b" };

		// 4 alternating calls — each individual hash appears only twice
		guard.check(agentId, tool, paramsA);
		guard.check(agentId, tool, paramsB);
		guard.check(agentId, tool, paramsA);
		guard.check(agentId, tool, paramsB);

		// Despite 4 total calls, each hash was seen only twice — below warn threshold
		const resultA = guard.check(agentId, tool, paramsA);
		expect(resultA.action).toBe("warn"); // 3rd time for A — at warn, not block
		expect(resultA.duplicateCount).toBe(3);

		const resultB = guard.check(agentId, tool, paramsB);
		expect(resultB.action).toBe("warn"); // 3rd time for B — at warn, not block
		expect(resultB.duplicateCount).toBe(3);

		// Neither is blocked — no false block from alternating pattern
		expect(resultA.action).not.toBe("block");
		expect(resultB.action).not.toBe("block");
	});

	it("evicts oldest agent when maxAgents exceeded", () => {
		const guard = new LoopGuard({ maxAgents: 3 });
		guard.check("agent-1", "tool", {});
		guard.check("agent-2", "tool", {});
		guard.check("agent-3", "tool", {});
		guard.check("agent-4", "tool", {}); // should evict agent-1
		// agent-1 has fresh state
		const result = guard.check("agent-1", "tool", {});
		expect(result.action).toBe("allow");
		expect(result.duplicateCount).toBe(1); // fresh start, only 1 call
	});

	it("throws on maxAgents < 1", () => {
		expect(() => new LoopGuard({ maxAgents: 0 })).toThrow("maxAgents must be positive");
		expect(() => new LoopGuard({ maxAgents: -1 })).toThrow("maxAgents must be positive");
	});

	it("custom thresholds are respected", () => {
		const guard = new LoopGuard({ warnThreshold: 2, blockThreshold: 3 });
		guard.check(agentId, tool, params);
		const warn = guard.check(agentId, tool, params);
		expect(warn.action).toBe("warn");

		const block = guard.check(agentId, tool, params);
		expect(block.action).toBe("block");
	});
});
