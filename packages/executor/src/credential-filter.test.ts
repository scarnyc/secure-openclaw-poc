import type { ToolResult } from "@sentinel/types";
import { describe, expect, it } from "vitest";
import { filterCredentials } from "./credential-filter.js";

function makeResult(output?: string, error?: string): ToolResult {
	return {
		manifestId: "test-id",
		success: !error,
		output,
		error,
		duration_ms: 0,
	};
}

describe("filterCredentials", () => {
	it("strips Anthropic API keys from output", () => {
		const result = makeResult("key is sk-ant-abc123-XYZ_def456-ghijk");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("sk-ant-");
		expect(filtered.output).toContain("[REDACTED]");
	});

	it("strips OpenAI-style keys from output", () => {
		const result = makeResult("sk-proj-aBcDeFgHiJkLmNoPqRsTuVwX");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("sk-proj-");
		expect(filtered.output).toContain("[REDACTED]");
	});

	it("strips GitHub tokens from output", () => {
		const result = makeResult("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("ghp_");
		expect(filtered.output).toContain("[REDACTED]");
	});

	it("strips AWS access keys from output", () => {
		const result = makeResult("AKIAIOSFODNN7EXAMPLE");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("AKIAIOSFODNN7EXAMPLE");
	});

	it("strips Bearer tokens from output", () => {
		const result = makeResult("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("eyJhbGciOiJ");
	});

	it("strips Slack tokens from output", () => {
		const result = makeResult("token: xoxb-123456-abcdef");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("xoxb-");
	});

	it("strips credentials from error field too", () => {
		const result = makeResult(undefined, "Failed: sk-ant-abc123-secretkey999");
		const filtered = filterCredentials(result);
		expect(filtered.error).not.toContain("sk-ant-");
		expect(filtered.error).toContain("[REDACTED]");
	});

	it("passes through output without credentials unchanged", () => {
		const result = makeResult("hello world, no secrets here");
		const filtered = filterCredentials(result);
		expect(filtered.output).toBe("hello world, no secrets here");
	});

	it("preserves undefined output/error", () => {
		const result = makeResult(undefined, undefined);
		const filtered = filterCredentials(result);
		expect(filtered.output).toBeUndefined();
		expect(filtered.error).toBeUndefined();
	});

	it("preserves other ToolResult fields", () => {
		const result = makeResult("clean output");
		const filtered = filterCredentials(result);
		expect(filtered.manifestId).toBe("test-id");
		expect(filtered.success).toBe(true);
		expect(filtered.duration_ms).toBe(0);
	});
});
