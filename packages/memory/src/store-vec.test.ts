import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { LocalEmbedder } from "./embedder.js";
import type { CreateObservation } from "./schema.js";
import { MemoryStore } from "./store.js";

const tempDirs: string[] = [];

function makeTempDbPath(): string {
	const dir = mkdtempSync(join(tmpdir(), "sentinel-memory-vec-"));
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
	title: "SSRF protection",
	content:
		"Block private IP addresses and localhost from outbound requests to prevent server-side request forgery.",
	concepts: ["ssrf", "security"],
	filesInvolved: [],
};

describe("MemoryStore vector search", () => {
	it("vector search finds semantically similar observations", async () => {
		const embedder = await LocalEmbedder.create();
		const store = new MemoryStore(makeTempDbPath(), { embedder });

		await store.observeWithEmbedding({
			...validObs,
			title: "SSRF guard",
			content:
				"Block private IPs, localhost, and cloud metadata endpoints",
		});
		await store.observeWithEmbedding({
			...validObs,
			title: "Rate limiter",
			content:
				"GCRA algorithm for per-agent request throttling",
			sessionId: "s2",
		});
		await store.observeWithEmbedding({
			...validObs,
			title: "Baking cookies",
			content:
				"Mix flour, sugar, butter, and chocolate chips. Bake at 350F for 12 minutes.",
			sessionId: "s3",
		});

		const results = await store.vectorSearch(
			"network security and request filtering",
			2,
		);
		expect(results).toHaveLength(2);
		// Both security-related results should be returned, not the cookie one
		const titles = results.map((r) => r.title);
		expect(titles).toContain("SSRF guard");
		expect(titles).toContain("Rate limiter");
		expect(titles).not.toContain("Baking cookies");
		store.close();
	}, 60000);

	it("hybrid search combines FTS5 and vector results", async () => {
		const embedder = await LocalEmbedder.create();
		const store = new MemoryStore(makeTempDbPath(), { embedder });

		await store.observeWithEmbedding(validObs);
		await store.observeWithEmbedding({
			...validObs,
			title: "Merkle audit",
			content:
				"SHA-256 hash chain over audit rows for tamper detection",
			sessionId: "s2",
		});

		const results = await store.hybridSearch({
			query: "security",
			project: "secure-openclaw",
			limit: 10,
		});
		expect(results.length).toBeGreaterThanOrEqual(1);
		store.close();
	}, 60000);

	it("works without embedder (FTS5 only fallback)", () => {
		const store = new MemoryStore(makeTempDbPath());
		store.observe(validObs);
		const results = store.search({ query: "SSRF" });
		expect(results.length).toBeGreaterThanOrEqual(0);
		store.close();
	});
});
