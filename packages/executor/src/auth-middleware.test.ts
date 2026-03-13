import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import type { SentinelConfig } from "@sentinel/types";
import type { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";
import type { ToolRegistry } from "./tools/registry.js";

let tempDir: string;
let auditLogger: AuditLogger;
let registry: ToolRegistry;

const BASE_CONFIG: SentinelConfig = {
	executor: { port: 3141, host: "127.0.0.1" },
	classifications: [
		{ tool: "read_file", defaultCategory: "read" },
		{ tool: "write_file", defaultCategory: "write" },
	],
	autoApproveReadOps: true,
	auditLogPath: "",
	vaultPath: "",
	gwsDefaultDeny: false,
	llm: { provider: "anthropic", model: "claude-sonnet-4-20250514", maxTokens: 4096 },
};

function createAppWithAuth(authToken?: string): Hono {
	const config: SentinelConfig = {
		...BASE_CONFIG,
		...(authToken !== undefined ? { authToken } : {}),
	};
	return createApp(config, auditLogger, registry);
}

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-auth-test-")));
	process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
	const dbPath = join(tempDir, "audit.db");
	auditLogger = new AuditLogger(dbPath);
	registry = createToolRegistry();
});

afterEach(() => {
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
	delete process.env.SENTINEL_ALLOWED_ROOTS;
});

describe("Auth middleware — no token configured (auth disabled)", () => {
	it("allows requests without Authorization header", async () => {
		const app = createAppWithAuth(); // no authToken
		const res = await app.request("/tools");
		expect(res.status).toBe(200);
	});
});

describe("Auth middleware — token configured", () => {
	const SECRET = "test-bearer-token-abc123";

	it("allows request with correct Bearer token", async () => {
		const app = createAppWithAuth(SECRET);
		const res = await app.request("/tools", {
			headers: { Authorization: `Bearer ${SECRET}` },
		});
		expect(res.status).toBe(200);
	});

	it("rejects request with wrong Bearer token", async () => {
		const app = createAppWithAuth(SECRET);
		const res = await app.request("/tools", {
			headers: { Authorization: "Bearer wrong-token" },
		});
		expect(res.status).toBe(401);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("Invalid token");
	});

	it("rejects request with no Authorization header", async () => {
		const app = createAppWithAuth(SECRET);
		const res = await app.request("/tools");
		expect(res.status).toBe(401);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("Authorization required");
	});

	it("rejects request with malformed header (no Bearer prefix)", async () => {
		const app = createAppWithAuth(SECRET);
		const res = await app.request("/tools", {
			headers: { Authorization: `Basic ${SECRET}` },
		});
		expect(res.status).toBe(401);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("Invalid authorization format");
	});

	it("rejects request with empty Bearer token", async () => {
		const app = createAppWithAuth(SECRET);
		const res = await app.request("/tools", {
			headers: { Authorization: "Bearer " },
		});
		expect(res.status).toBe(401);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("Invalid authorization format");
	});

	it("health endpoint accessible without auth even when token is configured", async () => {
		const app = createAppWithAuth(SECRET);
		const res = await app.request("/health");
		expect(res.status).toBe(200);
		const body = (await res.json()) as { status: string };
		expect(body.status).toBe("ok");
	});

	it("agent-card endpoint requires auth when token is configured", async () => {
		const app = createAppWithAuth(SECRET);
		const res = await app.request("/agent-card");
		expect(res.status).toBe(401);
	});

	it("execute endpoint requires auth when token is configured", async () => {
		const app = createAppWithAuth(SECRET);
		const res = await app.request("/execute", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ tool: "bash", parameters: { command: "echo hi" } }),
		});
		expect(res.status).toBe(401);
	});

	it("proxy endpoint requires auth when token is configured", async () => {
		const app = createAppWithAuth(SECRET);
		const res = await app.request("/proxy/llm/test");
		expect(res.status).toBe(401);
	});

	it("pending-confirmations endpoint requires auth when token is configured", async () => {
		const app = createAppWithAuth(SECRET);
		const res = await app.request("/pending-confirmations");
		expect(res.status).toBe(401);
	});

	it("rejects wrong token of same length as configured token", async () => {
		const app = createAppWithAuth(SECRET);
		// Verify that a token with same length but different content is rejected
		const wrongToken = "x".repeat(SECRET.length);
		const res = await app.request("/tools", {
			headers: { Authorization: `Bearer ${wrongToken}` },
		});
		expect(res.status).toBe(401);
	});
});
