import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import type { SentinelConfig } from "@sentinel/types";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	createResponseSigner,
	SIGNATURE_HEADER,
	verifyResponseSignature,
} from "./response-signer.js";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";
import type { ToolRegistry } from "./tools/registry.js";

let tempDir: string;
let auditLogger: AuditLogger;
let registry: ToolRegistry;

const DEFAULT_CONFIG: SentinelConfig = {
	executor: { port: 3141, host: "127.0.0.1" },
	classifications: [
		{ tool: "read_file", defaultCategory: "read" },
		{ tool: "bash", defaultCategory: "read" },
	],
	autoApproveReadOps: true,
	auditLogPath: "",
	vaultPath: "",
	gwsDefaultDeny: false,
	llm: { provider: "anthropic", model: "claude-sonnet-4-20250514", maxTokens: 4096 },
};

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-signer-test-")));
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

describe("verifyResponseSignature", () => {
	it("valid HMAC -> passes agent validation", () => {
		const secret = randomBytes(32);
		const body = JSON.stringify({ manifestId: "test-123", success: true, output: "hello" });
		const hmac = createHmac("sha256", secret).update(body).digest("hex");

		expect(verifyResponseSignature(body, hmac, secret)).toBe(true);
	});

	it("tampered body -> agent rejects", () => {
		const secret = randomBytes(32);
		const body = JSON.stringify({ manifestId: "test-123", success: true, output: "hello" });
		const hmac = createHmac("sha256", secret).update(body).digest("hex");

		const tamperedBody = JSON.stringify({ manifestId: "test-123", success: true, output: "pwned" });
		expect(verifyResponseSignature(tamperedBody, hmac, secret)).toBe(false);
	});

	it("wrong secret -> verification fails", () => {
		const secret1 = randomBytes(32);
		const secret2 = randomBytes(32);
		const body = "test body";
		const hmac = createHmac("sha256", secret1).update(body).digest("hex");

		expect(verifyResponseSignature(body, hmac, secret2)).toBe(false);
	});
});

describe("createResponseSigner middleware", () => {
	it("adds HMAC signature to JSON responses", async () => {
		const secret = randomBytes(32);
		const app = createApp(DEFAULT_CONFIG, auditLogger, registry, undefined, secret);

		const res = await app.request("/health");
		expect(res.status).toBe(200);

		const signature = res.headers.get(SIGNATURE_HEADER);
		expect(signature).toBeTruthy();
		expect(signature).not.toBe("streaming");

		// Verify the signature
		const body = await res.text();
		const expected = createHmac("sha256", secret).update(body).digest("hex");
		expect(signature).toBe(expected);
	});

	it("SSE -> 'streaming' marker header", async () => {
		const secret = randomBytes(32);
		const { Hono } = await import("hono");
		const testApp = new Hono();
		testApp.use("*", createResponseSigner(secret));
		testApp.get("/sse", () => {
			return new Response("data: test\n\n", {
				headers: { "Content-Type": "text/event-stream" },
			});
		});

		const res = await testApp.request("/sse");
		expect(res.headers.get(SIGNATURE_HEADER)).toBe("streaming");
	});

	it("no secret -> no signature header (backward compat)", async () => {
		// Create app WITHOUT hmacSecret
		const app = createApp(DEFAULT_CONFIG, auditLogger, registry);

		const res = await app.request("/health");
		expect(res.status).toBe(200);

		// No signature header when no secret configured
		expect(res.headers.get(SIGNATURE_HEADER)).toBeNull();
	});
});
