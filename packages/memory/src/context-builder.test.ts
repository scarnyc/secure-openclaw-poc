import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildSessionContext } from "./context-builder.js";
import { MemoryStore } from "./store.js";

const tempDirs: string[] = [];

function makeTempDbPath(): string {
	const dir = mkdtempSync(join(tmpdir(), "sentinel-context-"));
	tempDirs.push(dir);
	return join(dir, "memory.db");
}

afterEach(() => {
	for (const dir of tempDirs) {
		rmSync(dir, { recursive: true, force: true });
	}
	tempDirs.length = 0;
});

describe("buildSessionContext", () => {
	it("returns empty string when no summaries exist", () => {
		const store = new MemoryStore(makeTempDbPath());
		const context = buildSessionContext(store, "secure-openclaw", "claude-code");
		expect(context).toBe("");
		store.close();
	});

	it("includes last daily summary title and next_steps", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.writeSummary({
			project: "secure-openclaw",
			source: "developer",
			scope: "daily",
			periodStart: new Date(Date.now() - 86400000).toISOString(),
			periodEnd: new Date().toISOString(),
			title: "Memory store implementation",
			investigated: ["SQLite FTS5 patterns"],
			learned: ["Porter stemming works well for code search"],
			completed: ["Schema + validator"],
			nextSteps: ["Implement MemoryStore core", "Add vector search"],
		});

		const context = buildSessionContext(store, "secure-openclaw", "claude-code");
		expect(context).toContain("Memory store implementation");
		expect(context).toContain("Implement MemoryStore core");
		expect(context).toContain("Add vector search");
		store.close();
	});

	it("stays under 200 token budget (approx 800 chars)", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.writeSummary({
			project: "secure-openclaw",
			source: "developer",
			scope: "daily",
			periodStart: new Date(Date.now() - 86400000).toISOString(),
			periodEnd: new Date().toISOString(),
			title: "Big day of work",
			investigated: Array.from(
				{ length: 10 },
				(_, i) => `Investigated item ${i} with lots of detail`,
			),
			learned: Array.from({ length: 10 }, (_, i) => `Learned item ${i} with extensive description`),
			completed: Array.from({ length: 10 }, (_, i) => `Completed task ${i}`),
			nextSteps: Array.from({ length: 10 }, (_, i) => `Next step ${i} requiring careful work`),
		});

		const context = buildSessionContext(store, "secure-openclaw", "claude-code");
		// ~200 tokens ≈ ~800 characters
		expect(context.length).toBeLessThanOrEqual(1000);
		store.close();
	});
});
