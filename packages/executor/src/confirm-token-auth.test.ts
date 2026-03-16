import { randomBytes } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import type { SentinelConfig } from "@sentinel/types";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateConfirmToken } from "./confirm-token.js";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";

const AUTH_TOKEN = "test-bearer-secret-token";
const HMAC_SECRET = randomBytes(32);

const CONFIG: SentinelConfig = {
	executor: { port: 3141, host: "127.0.0.1" },
	classifications: [
		{ tool: "write_file", defaultCategory: "write" },
		{ tool: "read_file", defaultCategory: "read" },
	],
	autoApproveReadOps: true,
	auditLogPath: "",
	vaultPath: "",
	gwsDefaultDeny: false,
	authToken: AUTH_TOKEN,
	llm: { provider: "anthropic", model: "claude-sonnet-4-20250514", maxTokens: 4096 },
};

let tempDir: string;
let auditLogger: AuditLogger;

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-auth-test-")));
	auditLogger = new AuditLogger(join(tempDir, "audit.db"));
});

afterEach(() => {
	rmSync(tempDir, { recursive: true, force: true });
});

function makeApp() {
	const registry = createToolRegistry();
	return createApp(
		CONFIG,
		auditLogger,
		registry,
		undefined,
		HMAC_SECRET,
		undefined,
		undefined,
		undefined,
		"http://localhost:3141",
	);
}

function bearerHeaders(): Record<string, string> {
	return {
		"Content-Type": "application/json",
		Authorization: `Bearer ${AUTH_TOKEN}`,
	};
}

// Seed a pending confirmation so confirm-ui and confirm endpoints have data
async function seedConfirmation(app: ReturnType<typeof makeApp>["app"]): Promise<string> {
	// POST /confirm-only blocks until resolved, so we fire-and-forget
	const body = {
		tool: "write_file",
		params: { path: "/tmp/test.txt", content: "hello" },
		agentId: "test-agent",
		sessionId: "test-session",
	};
	// Fire the long-poll in background
	const promise = app.request("/confirm-only", {
		method: "POST",
		headers: bearerHeaders(),
		body: JSON.stringify(body),
	});

	// Wait a tick for registration
	await new Promise((r) => setTimeout(r, 50));

	// Get the manifestId from pending
	const pendingRes = await app.request("/pending-confirmations", {
		headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
	});
	const pending = (await pendingRes.json()) as Array<{ manifestId: string }>;
	if (pending.length === 0) throw new Error("No pending confirmations found");

	// Store the promise for later cleanup (resolve it so it doesn't hang)
	// We'll resolve it in individual tests
	return pending[0].manifestId;
}

describe("HMAC token auth bypass", () => {
	it("GET /confirm-ui/:id with valid HMAC token bypasses bearer auth", async () => {
		const { app } = makeApp();
		const manifestId = await seedConfirmation(app);
		const expiresAt = Date.now() + 300_000;
		const token = generateConfirmToken(manifestId, expiresAt, HMAC_SECRET);

		const res = await app.request(`/confirm-ui/${manifestId}?token=${token}&expires=${expiresAt}`);
		expect(res.status).toBe(200);
		const html = await res.text();
		expect(html).toContain("Action Requires Confirmation");
	});

	it("POST /confirm/:id with valid HMAC token resolves confirmation", async () => {
		const { app } = makeApp();
		const manifestId = await seedConfirmation(app);
		const expiresAt = Date.now() + 300_000;
		const token = generateConfirmToken(manifestId, expiresAt, HMAC_SECRET);

		const res = await app.request(`/confirm/${manifestId}?token=${token}&expires=${expiresAt}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ approved: true }),
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as { status: string };
		expect(body.status).toBe("approved");
	});

	it("GET /confirm-ui/:id with invalid HMAC token returns 403", async () => {
		const { app } = makeApp();
		const manifestId = await seedConfirmation(app);
		const expiresAt = Date.now() + 300_000;

		const res = await app.request(
			`/confirm-ui/${manifestId}?token=${"a".repeat(64)}&expires=${expiresAt}`,
		);
		expect(res.status).toBe(403);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("Invalid or expired");
	});

	it("GET /confirm-ui/:id with expired HMAC token returns 403", async () => {
		const { app } = makeApp();
		const manifestId = await seedConfirmation(app);
		const pastExpiry = Date.now() - 1000;
		const token = generateConfirmToken(manifestId, pastExpiry, HMAC_SECRET);

		const res = await app.request(`/confirm-ui/${manifestId}?token=${token}&expires=${pastExpiry}`);
		expect(res.status).toBe(403);
	});

	it("GET /confirm-ui/:id without token params requires bearer auth (401)", async () => {
		const { app } = makeApp();
		const manifestId = await seedConfirmation(app);

		// No bearer token, no HMAC token → 401
		const res = await app.request(`/confirm-ui/${manifestId}`);
		expect(res.status).toBe(401);
	});

	it("GET /confirm-ui/:id with only token param (missing expires) returns 400", async () => {
		const { app } = makeApp();
		const manifestId = await seedConfirmation(app);

		const res = await app.request(`/confirm-ui/${manifestId}?token=${"a".repeat(64)}`);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("Both");
	});

	it("POST /confirm/:id with HMAC token for different manifestId returns 403", async () => {
		const { app } = makeApp();
		const manifestId = await seedConfirmation(app);
		const expiresAt = Date.now() + 300_000;
		// Token signed for a different ID
		const tokenForOtherId = generateConfirmToken("different-id", expiresAt, HMAC_SECRET);

		const res = await app.request(
			`/confirm/${manifestId}?token=${tokenForOtherId}&expires=${expiresAt}`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ approved: true }),
			},
		);
		expect(res.status).toBe(403);
	});

	it("GET /confirmations/stream without bearer token returns 401", async () => {
		const { app } = makeApp();

		const res = await app.request("/confirmations/stream");
		expect(res.status).toBe(401);
	});
});
