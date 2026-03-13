import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import type { ActionManifest, AuditEntry, SentinelConfig, ToolResult } from "@sentinel/types";
import type { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";
import { ToolRegistry } from "./tools/registry.js";

let tempDir: string;
let auditLogger: AuditLogger;
let registry: ToolRegistry;
let app: Hono;

const DEFAULT_CONFIG: SentinelConfig = {
	executor: { port: 3141, host: "127.0.0.1" },
	classifications: [
		{ tool: "read_file", defaultCategory: "read" },
		{ tool: "write_file", defaultCategory: "write" },
		{ tool: "edit_file", defaultCategory: "write" },
	],
	autoApproveReadOps: true,
	auditLogPath: "",
	vaultPath: "",
	llm: { provider: "anthropic", model: "claude-sonnet-4-20250514", maxTokens: 4096 },
};

function makeManifest(overrides: Partial<ActionManifest> = {}): ActionManifest {
	return {
		id: crypto.randomUUID(),
		timestamp: new Date().toISOString(),
		tool: "bash",
		parameters: { command: "echo hello" },
		sessionId: "test-session",
		agentId: "test-agent",
		...overrides,
	};
}

async function postExecute(app: Hono, manifest: ActionManifest) {
	return app.request("/execute", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(manifest),
	});
}

beforeEach(() => {
	// Use realpathSync to resolve macOS /var -> /private/var symlink
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-exec-test-")));
	// Allow tmpdir paths so file-based tool tests work with cwd-default path guard
	process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
	const dbPath = join(tempDir, "audit.db");
	auditLogger = new AuditLogger(dbPath);
	registry = createToolRegistry();

	// Create app with auto-approve confirmFn (overridden per-test when needed)
	app = createApp(DEFAULT_CONFIG, auditLogger, registry);
});

afterEach(() => {
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
	delete process.env.SENTINEL_ALLOWED_ROOTS;
});

describe("GET /health", () => {
	it("returns 200 with status ok", async () => {
		const res = await app.request("/health");
		expect(res.status).toBe(200);
		const body = (await res.json()) as { status: string; version: string };
		expect(body.status).toBe("ok");
		expect(body.version).toBe("0.1.0");
	});
});

describe("GET /tools", () => {
	it("returns array of tool definitions", async () => {
		const res = await app.request("/tools");
		expect(res.status).toBe(200);
		const tools = (await res.json()) as Array<{ name: string; source: string }>;
		expect(Array.isArray(tools)).toBe(true);
		expect(tools.length).toBe(5);

		const names = tools.map((t) => t.name);
		expect(names).toContain("bash");
		expect(names).toContain("read_file");
		expect(names).toContain("write_file");
		expect(names).toContain("edit_file");
		expect(names).toContain("gws");

		for (const tool of tools) {
			expect(tool.source).toBe("builtin");
		}
	});
});

describe("GET /agent-card", () => {
	it("returns valid AgentCard", async () => {
		const res = await app.request("/agent-card");
		expect(res.status).toBe(200);
		const card = (await res.json()) as {
			name: string;
			url: string;
			version: string;
			capabilities: unknown[];
		};
		expect(card.name).toBe("Sentinel Executor");
		expect(card.url).toBe("http://127.0.0.1:3141");
		expect(card.version).toBe("0.1.0");
		expect(Array.isArray(card.capabilities)).toBe(true);
		expect(card.capabilities.length).toBeGreaterThan(0);
	});
});

describe("POST /execute", () => {
	it("auto-approves read_file (read category)", async () => {
		const testFile = join(tempDir, "test-read.txt");
		writeFileSync(testFile, "hello world");

		const manifest = makeManifest({
			tool: "read_file",
			parameters: { path: testFile },
		});
		const res = await postExecute(app, manifest);
		expect(res.status).toBe(200);

		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(true);
		expect(result.output).toBe("hello world");
		expect(result.manifestId).toBe(manifest.id);
	});

	it("auto-approves bash `ls` (read category)", async () => {
		const manifest = makeManifest({
			tool: "bash",
			parameters: { command: "ls" },
		});
		const res = await postExecute(app, manifest);
		expect(res.status).toBe(200);

		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(true);
	});

	it("returns confirmation-needed for write_file", async () => {
		const targetPath = join(tempDir, "write-test.txt");
		const manifest = makeManifest({
			tool: "write_file",
			parameters: { path: targetPath, content: "data" },
		});

		// We need a separate app that doesn't auto-confirm.
		// The default confirmFn waits for POST /confirm/:id.
		// So we send execute, then confirm it.
		const confirmPromise = postExecute(app, manifest);

		// Give the server a tick to register the pending confirmation
		await new Promise((r) => setTimeout(r, 50));

		// Confirm it
		const confirmRes = await app.request(`/confirm/${manifest.id}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ approved: true }),
		});
		expect(confirmRes.status).toBe(200);

		const result = (await (await confirmPromise).json()) as ToolResult;
		expect(result.success).toBe(true);
	});

	it("returns denied when user rejects confirmation", async () => {
		const targetPath = join(tempDir, "denied-test.txt");
		const manifest = makeManifest({
			tool: "write_file",
			parameters: { path: targetPath, content: "data" },
		});

		const confirmPromise = postExecute(app, manifest);
		await new Promise((r) => setTimeout(r, 50));

		await app.request(`/confirm/${manifest.id}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ approved: false }),
		});

		const result = (await (await confirmPromise).json()) as ToolResult;
		expect(result.success).toBe(false);
		expect(result.error).toContain("Denied by user");
	});

	it("blocks denied file paths", async () => {
		const manifest = makeManifest({
			tool: "read_file",
			parameters: { path: "/project/.env" },
		});
		const res = await postExecute(app, manifest);
		expect(res.status).toBe(422);

		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(false);
		expect(result.error).toContain("denied");
	});

	it("returns 400 for invalid manifest", async () => {
		const res = await app.request("/execute", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ invalid: true }),
		});
		expect(res.status).toBe(400);
	});

	it("logs audit entry after execution", async () => {
		const manifest = makeManifest({
			tool: "bash",
			parameters: { command: "echo audit-test" },
		});
		await postExecute(app, manifest);

		const entries = auditLogger.getRecent(10);
		expect(entries.length).toBeGreaterThanOrEqual(1);

		const entry = entries.find((e) => e.manifestId === manifest.id);
		expect(entry).toBeDefined();
		// biome-ignore lint/style/noNonNullAssertion: entry verified defined above
		expect(entry!.tool).toBe("bash");
		// biome-ignore lint/style/noNonNullAssertion: entry verified defined above
		expect(entry!.result).toBe("success");
	});

	it("logs audit for blocked operations", async () => {
		const manifest = makeManifest({
			tool: "read_file",
			parameters: { path: "/secrets/credential.key" },
		});
		await postExecute(app, manifest);

		const entries = auditLogger.getRecent(10);
		const entry = entries.find((e) => e.manifestId === manifest.id);
		expect(entry).toBeDefined();
		// biome-ignore lint/style/noNonNullAssertion: entry verified defined above
		expect(entry!.result).toBe("failure");
	});
});

describe("POST /confirm/:manifestId", () => {
	it("returns 404 for unknown manifestId", async () => {
		const res = await app.request("/confirm/nonexistent", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ approved: true }),
		});
		expect(res.status).toBe(404);
	});
});

describe("GET /pending-confirmations", () => {
	it("returns empty array when no pending", async () => {
		const res = await app.request("/pending-confirmations");
		expect(res.status).toBe(200);
		const body = (await res.json()) as Array<unknown>;
		expect(body).toEqual([]);
	});

	it("returns pending confirmation after execute request", async () => {
		const targetPath = join(tempDir, "pending-test.txt");
		const manifest = makeManifest({
			tool: "write_file",
			parameters: { path: targetPath, content: "data" },
		});

		// Start execute (it will block waiting for confirmation)
		const executePromise = postExecute(app, manifest);
		await new Promise((r) => setTimeout(r, 50));

		// Check pending
		const res = await app.request("/pending-confirmations");
		expect(res.status).toBe(200);
		const pending = (await res.json()) as Array<{
			manifestId: string;
			tool: string;
			category: string;
		}>;
		expect(pending.length).toBe(1);
		expect(pending[0].manifestId).toBe(manifest.id);
		expect(pending[0].tool).toBe("write_file");
		expect(pending[0].category).toBe("write");

		// Clean up: approve so execute resolves
		await app.request(`/confirm/${manifest.id}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ approved: true }),
		});
		await executePromise;
	});
});

describe("confirmation timeout (LOW-12)", () => {
	it("auto-denies pending confirmation after timeout", async () => {
		vi.useFakeTimers();

		const targetPath = join(tempDir, "timeout-test.txt");
		const manifest = makeManifest({
			tool: "write_file",
			parameters: { path: targetPath, content: "data" },
		});

		// Start execute — will block waiting for confirmation
		const executePromise = postExecute(app, manifest);

		// Give server a tick to register the pending confirmation
		await vi.advanceTimersByTimeAsync(50);

		// Verify confirmation is pending
		const pendingRes = await app.request("/pending-confirmations");
		const pending = (await pendingRes.json()) as Array<{ manifestId: string }>;
		expect(pending.length).toBe(1);
		expect(pending[0].manifestId).toBe(manifest.id);

		// Advance past the 5-minute timeout
		await vi.advanceTimersByTimeAsync(300_000);

		// Execute should have resolved with denial
		const res = await executePromise;
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(false);
		expect(result.error).toContain("Denied by user");

		// Pending confirmations should be cleared
		const afterRes = await app.request("/pending-confirmations");
		const afterPending = (await afterRes.json()) as Array<unknown>;
		expect(afterPending.length).toBe(0);

		vi.useRealTimers();
	});

	it("clears timeout when confirmation is resolved manually", async () => {
		vi.useFakeTimers();

		const targetPath = join(tempDir, "manual-confirm.txt");
		const manifest = makeManifest({
			tool: "write_file",
			parameters: { path: targetPath, content: "data" },
		});

		const executePromise = postExecute(app, manifest);
		await vi.advanceTimersByTimeAsync(50);

		// Confirm manually before timeout
		await app.request(`/confirm/${manifest.id}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ approved: true }),
		});

		const res = await executePromise;
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(true);

		vi.useRealTimers();
	});
});

describe("body size limits (LOW-17)", () => {
	it("rejects /execute with Content-Length > 10MB", async () => {
		const res = await app.request("/execute", {
			method: "POST",
			headers: {
				"Content-Length": "11000000",
				"Content-Type": "application/json",
			},
			body: "{}",
		});
		expect(res.status).toBe(413);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("too large");
	});

	it("rejects /proxy/llm/* with Content-Length > 25MB (I5/I7 fix)", async () => {
		const res = await app.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: {
				"Content-Length": String(26 * 1024 * 1024),
				"Content-Type": "application/json",
			},
			body: "{}",
		});
		expect(res.status).toBe(413);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("too large");
	});

	it("allows /proxy/llm/* with Content-Length under 25MB", async () => {
		// 24MB should be within the limit — test won't actually send 24MB,
		// but header check alone determines rejection
		const res = await app.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: {
				"Content-Length": String(24 * 1024 * 1024),
				"Content-Type": "application/json",
			},
			body: "{}",
		});
		// Should NOT be rejected by body size middleware
		expect(res.status).not.toBe(413);
	});

	it("allows normal-sized /execute requests", async () => {
		const manifest = makeManifest({
			tool: "bash",
			parameters: { command: "echo size-test" },
		});
		const res = await postExecute(app, manifest);
		// Should not be blocked by body size middleware
		expect(res.status).not.toBe(413);
	});

	it("rejects oversized body even without Content-Length header (chunked bypass defense)", async () => {
		// Create a body larger than 10MB without a Content-Length header
		const oversizedBody = "x".repeat(11 * 1024 * 1024);
		const res = await app.request("/execute", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: oversizedBody,
		});
		expect(res.status).toBe(413);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("too large");
	});
});

describe("M7: unhandled exception audit logging (I2)", () => {
	it("logs best-effort audit entry when handler throws", async () => {
		// Create a custom registry with a tool that throws to escape handleExecute
		const throwingRegistry = new ToolRegistry();
		throwingRegistry.registerBuiltin("crash-tool", async () => {
			throw new Error("Unhandled crash");
		});
		// Configure crash-tool as "read" + autoApproveReadOps so it bypasses confirmation
		const crashConfig: SentinelConfig = {
			...DEFAULT_CONFIG,
			autoApproveReadOps: true,
			classifications: [
				...DEFAULT_CONFIG.classifications,
				{ tool: "crash-tool", defaultCategory: "read" as const },
			],
		};
		const crashApp = createApp(crashConfig, auditLogger, throwingRegistry);

		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const manifest = makeManifest({ tool: "crash-tool", parameters: {} });
		const res = await postExecute(crashApp, manifest);

		expect(res.status).toBe(500);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("Internal execution error");

		// Verify audit trail contains a failure entry
		const entries = auditLogger.query({});
		const failureEntries = entries.filter((e: AuditEntry) => e.result === "failure");
		expect(failureEntries.length).toBeGreaterThanOrEqual(1);

		consoleSpy.mockRestore();
	});
});
