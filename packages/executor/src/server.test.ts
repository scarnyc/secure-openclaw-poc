import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import { getDefaultPolicy } from "@sentinel/policy";
import type { ActionManifest, SentinelConfig, ToolResult } from "@sentinel/types";
import type { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";
import type { ToolRegistry } from "./tools/registry.js";

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
	tempDir = mkdtempSync(join(tmpdir(), "sentinel-exec-test-"));
	const dbPath = join(tempDir, "audit.db");
	auditLogger = new AuditLogger(dbPath);
	registry = createToolRegistry();

	// Create app with auto-approve confirmFn (overridden per-test when needed)
	app = createApp(DEFAULT_CONFIG, getDefaultPolicy(), auditLogger, registry);
});

afterEach(() => {
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
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
		expect(tools.length).toBe(4);

		const names = tools.map((t) => t.name);
		expect(names).toContain("bash");
		expect(names).toContain("read_file");
		expect(names).toContain("write_file");
		expect(names).toContain("edit_file");

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
