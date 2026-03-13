import { beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";
import { executeGws, type GwsParams } from "./gws.js";
import {
	validateGwsAdminArgs,
	validateGwsArgs,
	validateGwsCalendarArgs,
	validateGwsDriveArgs,
	validateGwsGenericArgs,
	validateGwsEmailContentArgs,
} from "./gws-validation.js";

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

describe("validateGwsEmailContentArgs", () => {
	it("valid gmail send args pass", () => {
		const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
			to: ["alice@example.com"],
			subject: "Hello",
			body: "Test body",
		});
		expect(result.valid).toBe(true);
		expect(result.errors).toHaveLength(0);
	});

	it("missing `to` rejects", () => {
		const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
			subject: "Hello",
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toContain("to is required for gmail send");
	});

	it("invalid email format rejects", () => {
		const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
			to: ["not-an-email", "@missing.com"],
			subject: "Hello",
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(
			expect.arrayContaining([
				expect.stringContaining("invalid email"),
				expect.stringContaining("invalid email"),
			]),
		);
	});

	it(">50 recipients in `to` rejects", () => {
		const emails = Array.from({ length: 51 }, (_, i) => `user${i}@example.com`);
		const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
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
		const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
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
		const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
			to: ["alice@example.com"],
			subject: "Hello\r\nBCC: evil@example.com",
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining("CR or LF")]));
	});

	it("subject >998 chars rejects", () => {
		const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
			to: ["alice@example.com"],
			subject: "x".repeat(999),
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining("998")]));
	});

	it("non-gmail service passes without validation", () => {
		const result = validateGwsEmailContentArgs("drive", "files.create", {});
		expect(result.valid).toBe(true);
		expect(result.errors).toHaveLength(0);
	});

	it("non-send gmail method passes without validation", () => {
		const result = validateGwsEmailContentArgs("gmail", "users.messages.list", {});
		expect(result.valid).toBe(true);
		expect(result.errors).toHaveLength(0);
	});

	describe("raw MIME blocking", () => {
		it("args.raw on users.messages.send is rejected", () => {
			const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
				raw: btoa("From: me\r\nTo: you\r\n\r\nHello"),
				to: ["alice@example.com"],
				subject: "Hello",
			});
			expect(result.valid).toBe(false);
			expect(result.errors).toEqual(
				expect.arrayContaining([expect.stringContaining("raw MIME is not allowed")]),
			);
		});

		it("args.raw on drafts.create is rejected", () => {
			const result = validateGwsEmailContentArgs("gmail", "drafts.create", {
				raw: btoa("From: me\r\n\r\nDraft content"),
				subject: "Draft",
			});
			expect(result.valid).toBe(false);
			expect(result.errors).toEqual(
				expect.arrayContaining([expect.stringContaining("raw MIME is not allowed")]),
			);
		});

		it("args.raw alongside valid to/subject is still rejected", () => {
			const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
				raw: "anything",
				to: ["alice@example.com"],
				subject: "Hello",
				body: "Clean body",
			});
			expect(result.valid).toBe(false);
			expect(result.errors).toEqual(
				expect.arrayContaining([expect.stringContaining("raw MIME is not allowed")]),
			);
		});

		it("non-gmail method with raw passes (not gmail-scoped)", () => {
			const result = validateGwsEmailContentArgs("drive", "files.create", { raw: "data" });
			expect(result.valid).toBe(true);
		});
	});

	describe("draft validation", () => {
		it("drafts.create without to but with subject passes", () => {
			const result = validateGwsEmailContentArgs("gmail", "drafts.create", {
				subject: "Draft subject",
				body: "Draft body",
			});
			expect(result.valid).toBe(true);
			expect(result.errors).toHaveLength(0);
		});

		it("drafts.update with valid fields passes", () => {
			const result = validateGwsEmailContentArgs("gmail", "drafts.update", {
				subject: "Updated subject",
				body: "Updated body",
			});
			expect(result.valid).toBe(true);
			expect(result.errors).toHaveLength(0);
		});

		it("drafts.create without subject passes (subject optional for drafts)", () => {
			const result = validateGwsEmailContentArgs("gmail", "drafts.create", {
				body: "Draft body without subject",
			});
			expect(result.valid).toBe(true);
			expect(result.errors).toHaveLength(0);
		});

		it("drafts.update without subject passes", () => {
			const result = validateGwsEmailContentArgs("gmail", "drafts.update", {
				body: "Updated body",
			});
			expect(result.valid).toBe(true);
			expect(result.errors).toHaveLength(0);
		});

		it("send without subject rejects", () => {
			const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
				to: ["alice@example.com"],
				body: "No subject",
			});
			expect(result.valid).toBe(false);
			expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining("subject")]));
		});
	});

	it("valid args with cc + bcc pass", () => {
		const result = validateGwsEmailContentArgs("gmail", "users.messages.send", {
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

describe("validateGwsGenericArgs", () => {
	it("rejects oversized string", () => {
		const result = validateGwsGenericArgs({ data: "x".repeat(1_048_577) });
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("maximum length");
	});

	it("rejects oversized array", () => {
		const result = validateGwsGenericArgs({ items: Array.from({ length: 1001 }) });
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("maximum length");
	});

	it("rejects deeply nested object", () => {
		let obj: Record<string, unknown> = { val: "deep" };
		for (let i = 0; i < 12; i++) {
			obj = { nested: obj };
		}
		const result = validateGwsGenericArgs(obj);
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("depth");
	});

	it("passes normal args", () => {
		const result = validateGwsGenericArgs({ query: "test", limit: 10 });
		expect(result.valid).toBe(true);
	});
});

describe("validateGwsDriveArgs", () => {
	it("rejects path traversal (..)", () => {
		const result = validateGwsDriveArgs("files.get", { path: "../../etc/passwd" });
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("traversal");
	});

	it("rejects .env file targeting", () => {
		const result = validateGwsDriveArgs("files.get", { name: "config.env" });
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("sensitive");
	});

	it("rejects .pem file targeting", () => {
		const result = validateGwsDriveArgs("files.get", { name: "server.pem" });
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("sensitive");
	});

	it("passes normal file paths", () => {
		const result = validateGwsDriveArgs("files.get", { name: "report.pdf", folderId: "abc123" });
		expect(result.valid).toBe(true);
	});

	it("rejects nested path traversal (recursive scanning)", () => {
		const result = validateGwsDriveArgs("files.copy", {
			resource: { metadata: { filePath: "../../.env" } },
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(
			expect.arrayContaining([expect.stringContaining("traversal")]),
		);
	});

	it("rejects nested sensitive file targeting", () => {
		const result = validateGwsDriveArgs("files.copy", {
			resource: { name: "server.pem" },
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(
			expect.arrayContaining([expect.stringContaining("sensitive")]),
		);
	});
});

describe("validateGwsCalendarArgs", () => {
	it("rejects >200 attendees", () => {
		const attendees = Array.from({ length: 201 }, (_, i) => `user${i}@example.com`);
		const result = validateGwsCalendarArgs("events.insert", { attendees });
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("200");
	});

	it("rejects invalid attendee format", () => {
		const result = validateGwsCalendarArgs("events.insert", { attendees: ["not-an-email"] });
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("Invalid attendee");
	});

	it("accepts attendee objects with email field", () => {
		const result = validateGwsCalendarArgs("events.insert", {
			attendees: [{ email: "alice@example.com" }],
		});
		expect(result.valid).toBe(true);
	});

	it("passes normal calendar args without attendees", () => {
		const result = validateGwsCalendarArgs("events.list", { calendarId: "primary" });
		expect(result.valid).toBe(true);
	});
});

describe("validateGwsAdminArgs", () => {
	it("rejects users.delete", () => {
		const result = validateGwsAdminArgs("users.delete");
		expect(result.valid).toBe(false);
		expect(result.errors[0]).toContain("not allowed");
	});

	it("allows users.list", () => {
		const result = validateGwsAdminArgs("users.list");
		expect(result.valid).toBe(true);
	});

	it("allows users.get", () => {
		const result = validateGwsAdminArgs("users.get");
		expect(result.valid).toBe(true);
	});

	it("rejects unknown admin method", () => {
		const result = validateGwsAdminArgs("users.update");
		expect(result.valid).toBe(false);
	});
});

describe("validateGwsArgs (orchestrator)", () => {
	it("combines generic + gmail validation errors", () => {
		const result = validateGwsArgs("gmail", "users.messages.send", {
			raw: "bypass",
		});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining("raw MIME")]));
	});

	it("combines generic + drive validation", () => {
		const result = validateGwsArgs("drive", "files.get", { path: "../../etc/passwd" });
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining("traversal")]));
	});

	it("admin validation blocks non-read methods", () => {
		const result = validateGwsArgs("admin", "users.delete", {});
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining("not allowed")]));
	});

	it("passes unknown service through generic validation only", () => {
		const result = validateGwsArgs("sheets", "spreadsheets.get", { id: "abc" });
		expect(result.valid).toBe(true);
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
