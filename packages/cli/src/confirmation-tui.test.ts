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

	it("displays cannot-be-undone warning for write-irreversible actions", () => {
		const irreversibleReq: PendingConfirmation = {
			manifestId: "test-456",
			tool: "gws",
			parameters: { service: "gmail", method: "users.messages.send" },
			category: "write-irreversible",
			reason: "Irreversible action requires confirmation",
		};
		const output = formatConfirmationPrompt(irreversibleReq);
		expect(output).toContain("CANNOT BE UNDONE");
	});
});

describe("GWS email recipient display", () => {
	it("shows all recipients without truncation for GWS email send", () => {
		const req: PendingConfirmation = {
			manifestId: "test-789",
			tool: "gws",
			parameters: {
				service: "gmail",
				method: "users.messages.send",
				args: {
					to: ["alice@example.com", "bob@example.com"],
					subject: "Test email",
				},
			},
			category: "write-irreversible",
			reason: "Email send is irreversible",
		};
		const output = formatConfirmationPrompt(req);
		expect(output).toContain("alice@example.com");
		expect(output).toContain("bob@example.com");
	});

	it("shows count warning when >5 recipients", () => {
		const recipients = Array.from({ length: 8 }, (_, i) => `user${i}@example.com`);
		const req: PendingConfirmation = {
			manifestId: "test-790",
			tool: "gws",
			parameters: {
				service: "gmail",
				method: "users.messages.send",
				args: { to: recipients, subject: "Test" },
			},
			category: "write-irreversible",
			reason: "Email send is irreversible",
		};
		const output = formatConfirmationPrompt(req);
		expect(output).toContain("8 recipients total");
	});

	it("shows long recipient list fully visible (>200 chars total)", () => {
		const longRecipients = Array.from(
			{ length: 15 },
			(_, i) => `very-long-username-${i}@very-long-domain-name.example.com`,
		);
		const req: PendingConfirmation = {
			manifestId: "test-791",
			tool: "gws",
			parameters: {
				service: "gmail",
				method: "users.messages.send",
				args: { to: longRecipients, subject: "Test" },
			},
			category: "write-irreversible",
			reason: "Email send is irreversible",
		};
		const output = formatConfirmationPrompt(req);
		// Every recipient should be fully visible
		for (const r of longRecipients) {
			expect(output).toContain(r);
		}
	});

	it("still truncates non-GWS tool parameters at 200 chars", () => {
		const longReq: PendingConfirmation = {
			manifestId: "test-792",
			tool: "bash",
			parameters: { command: "x".repeat(300) },
			category: "dangerous",
			reason: "Network egress",
		};
		const output = formatConfirmationPrompt(longReq);
		expect(output).toContain("...");
		expect(output).not.toContain("x".repeat(300));
	});

	it("displays write-irreversible warning alongside recipient list", () => {
		const req: PendingConfirmation = {
			manifestId: "test-793",
			tool: "gws",
			parameters: {
				service: "gmail",
				method: "users.messages.send",
				args: {
					to: ["alice@example.com"],
					subject: "Test email",
				},
			},
			category: "write-irreversible",
			reason: "Email send is irreversible",
		};
		const output = formatConfirmationPrompt(req);
		expect(output).toContain("CANNOT BE UNDONE");
		expect(output).toContain("alice@example.com");
	});
});
