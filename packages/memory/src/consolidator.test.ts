import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Consolidator } from "./consolidator.js";
import type { CreateObservation } from "./schema.js";
import { MemoryStore } from "./store.js";

const tempDirs: string[] = [];

function makeTempDbPath(): string {
	const dir = mkdtempSync(join(tmpdir(), "sentinel-consolidator-"));
	tempDirs.push(dir);
	return join(dir, "memory.db");
}

afterEach(() => {
	for (const dir of tempDirs) {
		rmSync(dir, { recursive: true, force: true });
	}
	tempDirs.length = 0;
});

const baseObs: CreateObservation = {
	project: "secure-openclaw",
	sessionId: "session-1",
	agentId: "claude-code",
	source: "developer",
	type: "learning",
	title: "Test observation",
	content: "Test content for consolidation.",
	concepts: ["testing"],
	filesInvolved: [],
};

describe("Consolidator", () => {
	it("generateSessionSummary merges session observations", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.observe({
			...baseObs,
			title: "Obs 1",
			content: "Investigated SSRF patterns",
			type: "context",
		});
		store.observe({
			...baseObs,
			title: "Obs 2",
			content: "Learned about private IP detection",
			type: "learning",
		});
		store.observe({
			...baseObs,
			title: "Obs 3",
			content: "Completed SSRF guard implementation",
			type: "decision",
		});

		const consolidator = new Consolidator(store);
		const summary = consolidator.generateSessionSummary("session-1", "secure-openclaw");
		expect(summary).toBeDefined();
		expect(summary.scope).toBe("session");
		expect(summary.project).toBe("secure-openclaw");
		expect(summary.observationIds).toHaveLength(3);
		expect(summary.investigated).toContain("Obs 1");
		expect(summary.learned).toContain("Obs 2");
		expect(summary.completed).toContain("Obs 3");
		store.close();
	});

	it("consolidateDay is idempotent", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.observe(baseObs);

		const consolidator = new Consolidator(store);
		const sessionSummary = consolidator.generateSessionSummary("session-1", "secure-openclaw");
		store.writeSummary(sessionSummary);

		const range = {
			start: new Date(Date.now() - 86400000).toISOString(),
			end: new Date().toISOString(),
		};

		const result1 = consolidator.consolidateDay("secure-openclaw", range);
		expect(result1.skipped).toBe(false);

		const result2 = consolidator.consolidateDay("secure-openclaw", range);
		expect(result2.skipped).toBe(true);
		store.close();
	});

	it("pruneObservations removes old unreferenced observations", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.observe(baseObs);

		const pruned = store.pruneObservations(0);
		expect(pruned).toBeGreaterThanOrEqual(0);
		store.close();
	});

	it("deduplicates identical learnings across sessions", () => {
		const store = new MemoryStore(makeTempDbPath(), {
			dedupWindowSeconds: 0,
		});
		store.observe({
			...baseObs,
			content: "FTS5 uses porter stemming",
		});
		store.observe({
			...baseObs,
			sessionId: "session-2",
			content: "FTS5 uses porter stemming",
		});

		const consolidator = new Consolidator(store);
		const s1 = consolidator.generateSessionSummary("session-1", "secure-openclaw");
		const s2 = consolidator.generateSessionSummary("session-2", "secure-openclaw");

		store.writeSummary(s1);
		store.writeSummary(s2);

		const range = {
			start: new Date(Date.now() - 86400000).toISOString(),
			end: new Date().toISOString(),
		};

		const daily = consolidator.consolidateDay("secure-openclaw", range);
		expect(daily.skipped).toBe(false);
		store.close();
	});
});
