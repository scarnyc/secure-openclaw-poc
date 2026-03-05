import { describe, expect, it } from "vitest";
import { redactCredentials } from "./redact.js";

describe("redactCredentials", () => {
	it("redacts Anthropic API keys (sk-ant-*)", () => {
		const input = "key is sk-ant-api03-abc123def456ghi789";
		expect(redactCredentials(input)).toBe("key is [REDACTED]");
	});

	it("redacts OpenAI-style keys (sk-*)", () => {
		const input = "token: sk-proj-abcdefghijklmnopqrstuvwx";
		expect(redactCredentials(input)).toBe("token: [REDACTED]");
	});

	it("redacts GitHub personal access tokens (ghp_*)", () => {
		const input = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";
		expect(redactCredentials(input)).toBe("[REDACTED]");
	});

	it("redacts Slack bot tokens (xoxb-*)", () => {
		const input = "token: xoxb-123456789-abcdef";
		expect(redactCredentials(input)).toBe("token: [REDACTED]");
	});

	it("redacts Slack user tokens (xoxp-*)", () => {
		const input = "xoxp-999-888-777-abcdef123456";
		expect(redactCredentials(input)).toBe("[REDACTED]");
	});

	it("redacts AWS access keys (AKIA*)", () => {
		const input = "aws key: AKIAIOSFODNN7EXAMPLE";
		expect(redactCredentials(input)).toBe("aws key: [REDACTED]");
	});

	it("redacts Bearer tokens", () => {
		const input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test";
		expect(redactCredentials(input)).toBe("Authorization: [REDACTED]");
	});

	it("redacts long base64-like strings (40+ chars)", () => {
		const base64 = "A".repeat(50);
		const input = `data: ${base64} end`;
		expect(redactCredentials(input)).toBe("data: [REDACTED] end");
	});

	it("leaves normal text unchanged", () => {
		const input = "This is a normal log message with no secrets";
		expect(redactCredentials(input)).toBe(input);
	});

	it("redacts credentials in mixed text", () => {
		const input = "key is sk-ant-abc123def456ghij789 and more text here";
		const result = redactCredentials(input);
		expect(result).toContain("[REDACTED]");
		expect(result).not.toContain("sk-ant-");
		expect(result).toContain("and more text here");
	});

	it("redacts multiple credentials in same string", () => {
		const input = "keys: sk-ant-abc123def456ghij789 and xoxb-token-value";
		const result = redactCredentials(input);
		expect(result).not.toContain("sk-ant-");
		expect(result).not.toContain("xoxb-");
	});

	it("truncates strings longer than 500 chars", () => {
		// Use spaces to avoid matching base64 pattern
		const input = "hello world! ".repeat(50); // 650 chars
		const result = redactCredentials(input);
		expect(result.length).toBeLessThanOrEqual(500);
		expect(result).toContain("... [truncated]");
	});

	it("does not truncate strings at exactly 500 chars", () => {
		const input = "hello world! ".repeat(39).slice(0, 500); // exactly 500
		const result = redactCredentials(input);
		expect(result).toBe(input);
		expect(result.length).toBe(500);
	});

	it("handles empty string", () => {
		expect(redactCredentials("")).toBe("");
	});

	it("handles short sk- prefix without matching (too short)", () => {
		const input = "sk-short";
		// sk- followed by <20 chars should not match the OpenAI pattern
		expect(redactCredentials(input)).toBe("sk-short");
	});
});
