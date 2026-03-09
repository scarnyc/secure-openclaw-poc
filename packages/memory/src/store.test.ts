import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryQuotaError } from "./errors.js";
import type { CreateObservation } from "./schema.js";
import { MemoryStore } from "./store.js";

const tempDirs: string[] = [];

function makeTempDbPath(): string {
	const dir = mkdtempSync(join(tmpdir(), "sentinel-memory-"));
	tempDirs.push(dir);
	return join(dir, "memory.db");
}

afterEach(() => {
	for (const dir of tempDirs) {
		rmSync(dir, { recursive: true, force: true });
	}
	tempDirs.length = 0;
});

const validObs: CreateObservation = {
	project: "secure-openclaw",
	sessionId: "session-1",
	agentId: "claude-code",
	source: "developer",
	type: "learning",
	title: "Learned about FTS5",
	content: "FTS5 supports porter stemming for English text search.",
	concepts: ["fts5", "search"],
	filesInvolved: ["packages/memory/src/store.ts"],
};

describe("MemoryStore", () => {
	it("observe + getById round-trip", () => {
		const store = new MemoryStore(makeTempDbPath());
		const id = store.observe(validObs);
		expect(id).toBeDefined();
		const obs = store.getById(id);
		expect(obs).toBeDefined();
		expect(obs!.title).toBe("Learned about FTS5");
		expect(obs!.content).toBe(validObs.content);
		expect(obs!.project).toBe("secure-openclaw");
		store.close();
	});

	it("deduplicates identical content within 30-second window", () => {
		const store = new MemoryStore(makeTempDbPath());
		const id1 = store.observe(validObs);
		const id2 = store.observe(validObs);
		expect(id1).toBe(id2);
		store.close();
	});

	it("allows same content after dedup window passes", () => {
		const store = new MemoryStore(makeTempDbPath(), {
			dedupWindowSeconds: 0,
		});
		const id1 = store.observe(validObs);
		const id2 = store.observe(validObs);
		expect(id1).not.toBe(id2);
		store.close();
	});

	it("FTS5 search returns matching observations", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.observe(validObs);
		store.observe({
			...validObs,
			title: "SSRF guard",
			content: "Block private IPs",
			sessionId: "s2",
		});

		const results = store.search({ query: "porter stemming" });
		expect(results).toHaveLength(1);
		expect(results[0].title).toBe("Learned about FTS5");
		store.close();
	});

	it("FTS5 search with project filter", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.observe(validObs);
		store.observe({
			...validObs,
			project: "other-project",
			title: "Other FTS5",
			content: "FTS5 in other project with porter stemming.",
			sessionId: "s2",
		});

		const results = store.search({
			query: "porter",
			project: "secure-openclaw",
		});
		expect(results).toHaveLength(1);
		expect(results[0].project).toBe("secure-openclaw");
		store.close();
	});

	it("filter-only search (no FTS5 query)", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.observe(validObs);
		store.observe({
			...validObs,
			type: "error",
			title: "Error obs",
			content: "Something broke",
			sessionId: "s2",
		});

		const results = store.search({ type: "learning" });
		expect(results).toHaveLength(1);
		expect(results[0].type).toBe("learning");
		store.close();
	});

	it("search respects limit and offset", () => {
		const store = new MemoryStore(makeTempDbPath());
		for (let i = 0; i < 5; i++) {
			store.observe({
				...validObs,
				title: `Obs ${i}`,
				content: `Content for observation number ${i}`,
				sessionId: `s-${i}`,
			});
		}

		const page1 = store.search({ limit: 2, offset: 0 });
		expect(page1).toHaveLength(2);

		const page2 = store.search({ limit: 2, offset: 2 });
		expect(page2).toHaveLength(2);
		expect(page2[0].title).not.toBe(page1[0].title);
		store.close();
	});

	it("getStorageBytes tracks total content size", () => {
		const store = new MemoryStore(makeTempDbPath());
		const before = store.getStorageBytes();
		store.observe(validObs);
		const after = store.getStorageBytes();
		expect(after).toBeGreaterThan(before);
		store.close();
	});

	it("rejects write when global quota exceeded", () => {
		const store = new MemoryStore(makeTempDbPath(), { maxTotalBytes: 100 });
		store.observe(validObs);
		expect(() =>
			store.observe({
				...validObs,
				sessionId: "s2",
				content: "x".repeat(100),
			}),
		).toThrow(MemoryQuotaError);
		store.close();
	});

	it("getRecentByAgent returns observations for specific agent", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.observe(validObs);
		store.observe({
			...validObs,
			agentId: "other-agent",
			title: "Other",
			content: "Other content",
			sessionId: "s2",
		});

		const recent = store.getRecentByAgent(
			"secure-openclaw",
			"claude-code",
			10,
		);
		expect(recent).toHaveLength(1);
		expect(recent[0].agentId).toBe("claude-code");
		store.close();
	});

	it("close() doesn't error on double close", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.close();
		expect(() => store.close()).not.toThrow();
	});

	it("throws after close when trying to observe", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.close();
		expect(() => store.observe(validObs)).toThrow("MemoryStore is closed");
	});
});
