import { beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";
import { executeGws, type GwsParams } from "./gws.js";
import { validateGwsSendArgs } from "./gws-validation.js";

// Mock execa for the executeGws integration test
vi.mock("execa", () => ({
	execa: vi.fn(),
}));

vi.mock("./gws-integrity.js", () => ({
	ensureGwsIntegrity: vi.fn(),
	isServiceAllowed: vi.fn(),
}));

import { execa } from "execa";
import { ensureGwsIntegrity, isServiceAllowed } from "./gws-integrity.js";

const mockExeca = execa as unknown as MockInstance;
const mockEnsureGwsIntegrity = ensureGwsIntegrity as unknown as MockInstance;
const mockIsServiceAllowed = isServiceAllowed as unknown as MockInstance;

describe("validateGwsSendArgs", () => {
	it("valid gmail send args pass", () => {
		const result = validateGwsSendArgs("gmail", "users.messages.send", {
			to: ["alice@example.com"],
			subject: "Hello",
			body: "Test body",
		});
		expect(result.valid).toBe(true);
		expect(result.errors).toHaveLength(0);
	});

	it("missing `to` rejects", () => {
		const result = validateGwsSendArgs("gmail", "users.messages.send", {
			subject: "Hello",
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toContain("to is required for gmail send");
	});

	it("invalid email format rejects", () => {
		const result = validateGwsSendArgs("gmail", "users.messages.send", {
			to: ["not-an-email", "@missing.com"],
			subject: "Hello",
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(
			expect.arrayContaining([
				expect.stringContaining("not-an-email"),
				expect.stringContaining("@missing.com"),
			]),
		);
	});

	it(">50 recipients in `to` rejects", () => {
		const emails = Array.from({ length: 51 }, (_, i) => `user${i}@example.com`);
		const result = validateGwsSendArgs("gmail", "users.messages.send", {
			to: emails,
			subject: "Hello",
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(
			expect.arrayContaining([expect.stringContaining("exceeds maximum of 50")]),
		);
	});

	it("total >100 recipients rejects", () => {
		const toEmails = Array.from({ length: 40 }, (_, i) => `to${i}@example.com`);
		const ccEmails = Array.from({ length: 35 }, (_, i) => `cc${i}@example.com`);
		const bccEmails = Array.from({ length: 30 }, (_, i) => `bcc${i}@example.com`);
		const result = validateGwsSendArgs("gmail", "users.messages.send", {
			to: toEmails,
			cc: ccEmails,
			bcc: bccEmails,
			subject: "Hello",
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(
			expect.arrayContaining([expect.stringContaining("exceeds maximum of 100")]),
		);
	});

	it("CRLF in subject rejects", () => {
		const result = validateGwsSendArgs("gmail", "users.messages.send", {
			to: ["alice@example.com"],
			subject: "Hello\r\nBCC: evil@example.com",
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining("CR or LF")]));
	});

	it("subject >998 chars rejects", () => {
		const result = validateGwsSendArgs("gmail", "users.messages.send", {
			to: ["alice@example.com"],
			subject: "x".repeat(999),
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining("998")]));
	});

	it("non-gmail service passes without validation", () => {
		const result = validateGwsSendArgs("drive", "files.create", {});
		expect(result.valid).toBe(true);
		expect(result.errors).toHaveLength(0);
	});

	it("non-send gmail method passes without validation", () => {
		const result = validateGwsSendArgs("gmail", "users.messages.list", {});
		expect(result.valid).toBe(true);
		expect(result.errors).toHaveLength(0);
	});

	it("valid args with cc + bcc pass", () => {
		const result = validateGwsSendArgs("gmail", "users.messages.send", {
			to: ["alice@example.com"],
			cc: ["bob@example.com"],
			bcc: ["carol@example.com"],
			subject: "Hello",
			body: "Test body",
		});
		expect(result.valid).toBe(true);
		expect(result.errors).toHaveLength(0);
	});
});

describe("executeGws with validation", () => {
	beforeEach(() => {
		vi.resetAllMocks();
		mockEnsureGwsIntegrity.mockResolvedValue({
			ok: true,
			binaryPath: "/usr/local/bin/gws",
			version: "1.0.0",
			warnings: [],
		});
		mockIsServiceAllowed.mockReturnValue(true);
	});

	it("returns failure without calling execa when args are invalid", async () => {
		const params: GwsParams = {
			service: "gmail",
			method: "users.messages.send",
			args: {
				to: ["not-an-email"],
				subject: "Hello\r\nBCC: evil@example.com",
			},
		};
		const result = await executeGws(params, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("GWS parameter validation failed");
		expect(mockExeca).not.toHaveBeenCalled();
	});
});
