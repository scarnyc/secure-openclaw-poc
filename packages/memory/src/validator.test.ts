import { describe, expect, it } from "vitest";
import type { CreateObservation } from "./schema.js";
import { validateObservation } from "./validator.js";

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

describe("Invariant #4: Memory size caps", () => {
	it("rejects observation exceeding 10KB content limit", () => {
		const result = validateObservation({
			...validObs,
			content: "x".repeat(10241),
		});
		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.code).toBe("SCHEMA_INVALID");
		}
	});

	it("rejects title exceeding 200 chars", () => {
		const result = validateObservation({
			...validObs,
			title: "x".repeat(201),
		});
		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.code).toBe("SCHEMA_INVALID");
		}
	});

	it("accepts observation at exactly 10KB content limit", () => {
		const result = validateObservation({
			...validObs,
			content: "x".repeat(10240),
		});
		expect(result.valid).toBe(true);
	});

	it("rejects concepts array exceeding 50 items", () => {
		const result = validateObservation({
			...validObs,
			concepts: Array.from({ length: 51 }, (_, i) => `c${i}`),
		});
		expect(result.valid).toBe(false);
	});
});

describe("Invariant #5: No credentials in memory", () => {
	it("strips Anthropic API key from content", () => {
		const result = validateObservation({
			...validObs,
			content: "Found key sk-ant-api03-secret123abc456def in config",
		});
		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.sanitized.content).not.toContain("sk-ant-");
			expect(result.sanitized.content).toContain("[REDACTED]");
		}
	});

	it("strips OpenAI API key from content", () => {
		const result = validateObservation({
			...validObs,
			content: "Key is sk-proj-abcdef1234567890abcdef",
		});
		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.sanitized.content).not.toContain("sk-proj-");
			expect(result.sanitized.content).toContain("[REDACTED]");
		}
	});

	it("strips credentials from title", () => {
		const result = validateObservation({
			...validObs,
			title: "Found sk-ant-api03-xyz in logs",
		});
		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.sanitized.title).not.toContain("sk-ant-");
		}
	});

	it("strips PII (SSN) from content", () => {
		const result = validateObservation({
			...validObs,
			content: "User SSN is 123-45-6789",
		});
		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.sanitized.content).toContain("[PII_REDACTED]");
			expect(result.sanitized.content).not.toContain("123-45-6789");
		}
	});

	it("strips PII (email) from content", () => {
		const result = validateObservation({
			...validObs,
			content: "Contact user@example.com for details",
		});
		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.sanitized.content).toContain("[PII_REDACTED]");
		}
	});

	it("rejects observation that is entirely a credential", () => {
		const result = validateObservation({
			...validObs,
			content: "sk-ant-api03-secretkey123abc456def789",
		});
		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.code).toBe("CONTENT_ONLY_SENSITIVE");
		}
	});

	it("rejects observation that is entirely PII", () => {
		const result = validateObservation({
			...validObs,
			content: "123-45-6789",
		});
		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.code).toBe("CONTENT_ONLY_SENSITIVE");
		}
	});

	it("accepts observation with mixed content and credentials", () => {
		const result = validateObservation({
			...validObs,
			content: "The API key sk-ant-api03-secret was found in the config file at line 42",
		});
		expect(result.valid).toBe(true);
		if (result.valid) {
			expect(result.sanitized.content).toContain("config file at line 42");
			expect(result.sanitized.content).toContain("[REDACTED]");
		}
	});
});

describe("validateObservation: invalid input", () => {
	it("rejects non-object input", () => {
		const result = validateObservation("not an object");
		expect(result.valid).toBe(false);
		if (!result.valid) {
			expect(result.code).toBe("SCHEMA_INVALID");
		}
	});

	it("rejects missing required fields", () => {
		const result = validateObservation({ project: "test" });
		expect(result.valid).toBe(false);
	});
});
