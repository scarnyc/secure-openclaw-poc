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

	it("strips Gemini API keys from output", () => {
		const result = makeResult("key: AIzaSyDaGmWKa4JsXZ7RGmKQv_abcdefghijklmnop");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("AIzaSyD");
		expect(filtered.output).toContain("[REDACTED]");
	});

	it("strips database connection strings from output", () => {
		const result = makeResult("db: postgres://user:pass@host:5432/mydb");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("postgres://");
		expect(filtered.output).toContain("[REDACTED]");
	});

	it("strips MongoDB connection strings from output", () => {
		const result = makeResult("uri: mongodb+srv://admin:secret@cluster.example.com/db");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("mongodb+srv://");
		expect(filtered.output).toContain("[REDACTED]");
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

describe("filterCredentials: PII scrubbing", () => {
	it("strips SSN from output", () => {
		const result = makeResult("SSN: 123-45-6789");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("123-45-6789");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("strips phone number (XXX) XXX-XXXX from output", () => {
		const result = makeResult("Call (555) 123-4567");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("(555) 123-4567");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("strips phone number XXX-XXX-XXXX from output", () => {
		const result = makeResult("Phone: 555-123-4567");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("555-123-4567");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("strips international phone +1XXXXXXXXXX from output", () => {
		const result = makeResult("Mobile: +15551234567");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("+15551234567");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("strips email address from output", () => {
		const result = makeResult("Email: john.doe@example.com");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("john.doe@example.com");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("strips salary from output", () => {
		const result = makeResult("Expected: $150,000");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("$150,000");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("strips salary shorthand $85K from output", () => {
		const result = makeResult("Range: $85K-$120K");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("$85K");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("strips LinkedIn URL from output", () => {
		const result = makeResult("Profile: https://www.linkedin.com/in/johndoe/");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("linkedin.com/in/johndoe");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("strips GitHub URL from output", () => {
		const result = makeResult("Code: https://github.com/johndoe");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("github.com/johndoe");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("passes through plain text unchanged", () => {
		const result = makeResult("hello world, no PII here");
		const filtered = filterCredentials(result);
		expect(filtered.output).toBe("hello world, no PII here");
	});

	it("does NOT redact small dollar amounts ($5, $10)", () => {
		const result = makeResult("Price: $5 and $10 and $99");
		const filtered = filterCredentials(result);
		expect(filtered.output).toContain("$5");
		expect(filtered.output).toContain("$10");
		expect(filtered.output).toContain("$99");
	});

	it("redacts salary-level amounts ($150,000)", () => {
		const result = makeResult("Expected: $150,000.00");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("$150,000");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("does NOT redact GitHub repo URLs", () => {
		const result = makeResult("See https://github.com/nodejs/node for details");
		const filtered = filterCredentials(result);
		expect(filtered.output).toContain("github.com/nodejs/node");
	});

	it("redacts GitHub profile URLs (no repo path)", () => {
		const result = makeResult("Profile: https://github.com/johndoe");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("github.com/johndoe");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});

	it("strips both credentials and PII in same string", () => {
		const result = makeResult("key: sk-ant-abc123-testkey456789012345 phone: 555-123-4567");
		const filtered = filterCredentials(result);
		expect(filtered.output).not.toContain("sk-ant-");
		expect(filtered.output).not.toContain("555-123-4567");
		expect(filtered.output).toContain("[REDACTED]");
		expect(filtered.output).toContain("[PII_REDACTED]");
	});
});
