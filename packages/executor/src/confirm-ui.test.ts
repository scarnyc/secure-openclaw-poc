import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createConfirmUiHandler } from "./confirm-ui.js";

function makeApp(pendingConfirmations: Map<string, unknown>) {
	const app = new Hono();
	app.get(
		"/confirm-ui/:manifestId",
		createConfirmUiHandler(
			pendingConfirmations as Parameters<typeof createConfirmUiHandler>[0],
			"http://localhost:3141",
		),
	);
	return app;
}

function makePending(overrides: Record<string, unknown> = {}) {
	return {
		manifest: {
			id: "test-id",
			tool: "send-email",
			parameters: { to: "alice@example.com", subject: "Hello" },
		},
		decision: {
			category: "write",
			reason: "Sends an email",
			action: "confirm",
		},
		resolve: () => {},
		...overrides,
	};
}

describe("confirm-ui handler", () => {
	it("returns 200 HTML with tool details for valid manifestId", async () => {
		const pending = new Map();
		pending.set("test-id", makePending());
		const app = makeApp(pending);

		const res = await app.request("/confirm-ui/test-id");
		expect(res.status).toBe(200);

		const html = await res.text();
		expect(html).toContain("send-email");
		expect(html).toContain("write");
		expect(html).toContain("Sends an email");
	});

	it("returns 404 for unknown manifestId", async () => {
		const pending = new Map();
		const app = makeApp(pending);

		const res = await app.request("/confirm-ui/nonexistent");
		expect(res.status).toBe(404);

		const html = await res.text();
		expect(html).toContain("Confirmation not found");
	});

	it("includes Approve/Deny buttons with correct POST target", async () => {
		const pending = new Map();
		pending.set("test-id", makePending());
		const app = makeApp(pending);

		const res = await app.request("/confirm-ui/test-id");
		const html = await res.text();

		expect(html).toContain("Approve");
		expect(html).toContain("Deny");
		expect(html).toContain("/confirm/test-id");
	});

	it("redacts credentials from parameters", async () => {
		const fakeKey = ["sk", "ant", "api03", "abc123def456ghi789jkl012"].join("-");
		const pending = new Map();
		pending.set(
			"test-id",
			makePending({
				manifest: {
					id: "test-id",
					tool: "call-api",
					parameters: { apiKey: fakeKey },
				},
			}),
		);
		const app = makeApp(pending);

		const res = await app.request("/confirm-ui/test-id");
		const html = await res.text();

		expect(html).not.toContain(fakeKey);
		expect(html).toContain("REDACTED");
	});

	it("shows irreversible warning banner for write-irreversible category", async () => {
		const pending = new Map();
		pending.set(
			"test-id",
			makePending({
				decision: {
					category: "write-irreversible",
					reason: "Sends permanent email",
					action: "confirm",
				},
			}),
		);
		const app = makeApp(pending);

		const res = await app.request("/confirm-ui/test-id");
		const html = await res.text();

		expect(html).toContain("THIS ACTION CANNOT BE UNDONE");
	});
});
