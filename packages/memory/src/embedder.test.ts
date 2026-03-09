import { describe, expect, it } from "vitest";
import { LocalEmbedder } from "./embedder.js";

function cosineSimilarity(a: Float32Array, b: Float32Array): number {
	let dot = 0;
	let normA = 0;
	let normB = 0;
	for (let i = 0; i < a.length; i++) {
		dot += a[i] * b[i];
		normA += a[i] * a[i];
		normB += b[i] * b[i];
	}
	return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

describe("Embedder", () => {
	it("LocalEmbedder returns correct dimensions", async () => {
		const embedder = await LocalEmbedder.create();
		expect(embedder.dimensions).toBe(384);
		expect(embedder.model).toBe("Xenova/bge-small-en-v1.5");
	}, 60000);

	it("embeds text to Float32Array of correct length", async () => {
		const embedder = await LocalEmbedder.create();
		const embedding = await embedder.embed(
			"FTS5 supports porter stemming",
		);
		expect(embedding).toBeInstanceOf(Float32Array);
		expect(embedding.length).toBe(384);
	}, 60000);

	it("similar texts have higher cosine similarity than unrelated texts", async () => {
		const embedder = await LocalEmbedder.create();
		const a = await embedder.embed(
			"SQLite full text search with FTS5",
		);
		const b = await embedder.embed(
			"FTS5 keyword search in SQLite database",
		);
		const c = await embedder.embed(
			"How to bake chocolate chip cookies",
		);

		const simAB = cosineSimilarity(a, b);
		const simAC = cosineSimilarity(a, c);
		expect(simAB).toBeGreaterThan(simAC);
	}, 60000);
});
