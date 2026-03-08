import { describe, expect, it } from "vitest";
import {
	BASH_OUTPUT_LIMIT,
	HTTP_OUTPUT_LIMIT,
	truncateBashOutput,
	truncateOutput,
} from "./output-truncation.js";

describe("output truncation", () => {
	it("returns short output unchanged", () => {
		const output = "hello world";
		expect(truncateOutput(output, 1024)).toBe(output);
	});

	it("truncates output exceeding limit", () => {
		const output = "A".repeat(1000);
		const result = truncateOutput(output, 100);
		expect(result).toContain("[OUTPUT TRUNCATED");
		expect(Buffer.byteLength(result, "utf-8")).toBeLessThan(1000);
	});

	it("truncation notice is appended", () => {
		const output = "x".repeat(200);
		const result = truncateOutput(output, 50);
		expect(result).toMatch(/\[OUTPUT TRUNCATED — exceeded maximum size\]$/);
	});

	it("handles exact boundary — no truncation", () => {
		const output = "A".repeat(100);
		expect(truncateOutput(output, 100)).toBe(output);
	});

	it("handles one byte over boundary — truncates", () => {
		const output = "A".repeat(101);
		const result = truncateOutput(output, 100);
		expect(result).toContain("[OUTPUT TRUNCATED");
	});

	it("handles multi-byte UTF-8 characters safely", () => {
		// Each emoji is 4 bytes in UTF-8
		const output = "🔒".repeat(30); // 120 bytes
		const result = truncateOutput(output, 50);
		// Should not produce invalid UTF-8
		expect(result).toContain("[OUTPUT TRUNCATED");
		// Verify the truncated part is valid UTF-8 (no replacement chars from malformed sequences)
		const truncatedPart = result.split("\n\n[OUTPUT TRUNCATED")[0];
		expect(truncatedPart).not.toContain("\uFFFD");
	});

	it("handles empty output", () => {
		expect(truncateOutput("", 100)).toBe("");
	});
});

describe("truncateBashOutput", () => {
	it("uses 50KB limit", () => {
		expect(BASH_OUTPUT_LIMIT).toBe(50 * 1024);
	});

	it("passes through output under 50KB", () => {
		const output = "A".repeat(1000);
		expect(truncateBashOutput(output)).toBe(output);
	});

	it("truncates output over 50KB", () => {
		const output = "A".repeat(60 * 1024);
		const result = truncateBashOutput(output);
		expect(result).toContain("[OUTPUT TRUNCATED");
		expect(result.length).toBeLessThan(output.length);
	});
});

describe("HTTP_OUTPUT_LIMIT constant", () => {
	it("is 10MB", () => {
		expect(HTTP_OUTPUT_LIMIT).toBe(10 * 1024 * 1024);
	});
});
