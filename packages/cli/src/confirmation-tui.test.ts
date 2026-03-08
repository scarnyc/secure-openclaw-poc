import { describe, expect, it } from "vitest";
import { formatConfirmationPrompt, type PendingConfirmation } from "./confirmation-tui.js";

const SAMPLE: PendingConfirmation = {
	manifestId: "test-123",
	tool: "bash",
	parameters: { command: "curl https://example.com" },
	category: "dangerous",
	reason: "Network egress",
};

describe("formatConfirmationPrompt", () => {
	it("includes tool name", () => {
		const output = formatConfirmationPrompt(SAMPLE);
		expect(output).toContain("bash");
	});

	it("includes category", () => {
		const output = formatConfirmationPrompt(SAMPLE);
		expect(output).toContain("dangerous");
	});

	it("includes reason", () => {
		const output = formatConfirmationPrompt(SAMPLE);
		expect(output).toContain("Network egress");
	});

	it("includes parameter key and value", () => {
		const output = formatConfirmationPrompt(SAMPLE);
		expect(output).toContain("command");
		expect(output).toContain("curl https://example.com");
	});

	it("truncates long parameter values", () => {
		const longReq: PendingConfirmation = {
			...SAMPLE,
			parameters: { data: "x".repeat(300) },
		};
		const output = formatConfirmationPrompt(longReq);
		expect(output).toContain("...");
		// Should NOT contain the full 300-char string
		expect(output).not.toContain("x".repeat(300));
	});
});
