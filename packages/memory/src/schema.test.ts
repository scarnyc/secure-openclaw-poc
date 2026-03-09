import { describe, expect, it } from "vitest";
import { CreateObservationSchema, CreateSummarySchema, SearchQuerySchema } from "./schema.js";

describe("CreateObservationSchema", () => {
	const validObs = {
		project: "secure-openclaw",
		sessionId: "session-1",
		agentId: "claude-code",
		source: "developer" as const,
		type: "learning" as const,
		title: "Learned about FTS5",
		content: "FTS5 supports porter stemming for English text search.",
		concepts: ["fts5", "search"],
		filesInvolved: ["packages/memory/src/store.ts"],
	};

	it("accepts valid observation", () => {
		const result = CreateObservationSchema.safeParse(validObs);
		expect(result.success).toBe(true);
	});

	it("rejects content exceeding 10KB", () => {
		const result = CreateObservationSchema.safeParse({
			...validObs,
			content: "x".repeat(10241),
		});
		expect(result.success).toBe(false);
	});

	it("rejects title exceeding 200 chars", () => {
		const result = CreateObservationSchema.safeParse({
			...validObs,
			title: "x".repeat(201),
		});
		expect(result.success).toBe(false);
	});

	it("rejects concepts array exceeding 50 items", () => {
		const result = CreateObservationSchema.safeParse({
			...validObs,
			concepts: Array.from({ length: 51 }, (_, i) => `concept-${i}`),
		});
		expect(result.success).toBe(false);
	});

	it("rejects files_involved array exceeding 100 items", () => {
		const result = CreateObservationSchema.safeParse({
			...validObs,
			filesInvolved: Array.from({ length: 101 }, (_, i) => `file-${i}.ts`),
		});
		expect(result.success).toBe(false);
	});

	it("rejects invalid source", () => {
		const result = CreateObservationSchema.safeParse({
			...validObs,
			source: "unknown",
		});
		expect(result.success).toBe(false);
	});

	it("rejects invalid type", () => {
		const result = CreateObservationSchema.safeParse({
			...validObs,
			type: "invalid",
		});
		expect(result.success).toBe(false);
	});

	it("defaults agentId to claude-code", () => {
		const { agentId, ...withoutAgent } = validObs;
		const result = CreateObservationSchema.safeParse(withoutAgent);
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.agentId).toBe("claude-code");
		}
	});

	it("defaults concepts to empty array", () => {
		const { concepts, ...withoutConcepts } = validObs;
		const result = CreateObservationSchema.safeParse(withoutConcepts);
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.concepts).toEqual([]);
		}
	});
});

describe("SearchQuerySchema", () => {
	it("accepts empty query (filter-only)", () => {
		const result = SearchQuerySchema.safeParse({});
		expect(result.success).toBe(true);
	});

	it("rejects limit exceeding 100", () => {
		const result = SearchQuerySchema.safeParse({ limit: 101 });
		expect(result.success).toBe(false);
	});

	it("defaults limit to 20", () => {
		const result = SearchQuerySchema.safeParse({});
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.limit).toBe(20);
		}
	});
});

describe("CreateSummarySchema", () => {
	it("rejects summary body field exceeding 5KB", () => {
		const result = CreateSummarySchema.safeParse({
			project: "test",
			source: "developer",
			scope: "session",
			periodStart: "2026-03-09T00:00:00.000Z",
			periodEnd: "2026-03-09T23:59:59.000Z",
			title: "Daily summary",
			learned: ["x".repeat(5121)],
		});
		expect(result.success).toBe(false);
	});
});
