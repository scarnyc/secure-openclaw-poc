import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import type { ClassifyResponse, SentinelConfig } from "@sentinel/types";
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
		{ tool: "bash", defaultCategory: "dangerous" },
	],
	autoApproveReadOps: true,
	auditLogPath: "",
	vaultPath: "",
	gwsDefaultDeny: false,
	llm: { provider: "anthropic", model: "claude-sonnet-4-20250514", maxTokens: 4096 },
};

async function postClassify(app: Hono, body: Record<string, unknown>): Promise<Response> {
	return app.request("/classify", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-classify-test-")));
	const dbPath = join(tempDir, "audit.db");
	auditLogger = new AuditLogger(dbPath);
	registry = createToolRegistry();
	app = createApp(DEFAULT_CONFIG, auditLogger, registry);
});

afterEach(() => {
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
});

describe("POST /classify", () => {
	it("returns auto_approve for read-classified tools", async () => {
		const res = await postClassify(app, {
			tool: "read_file",
			params: { path: "/tmp/test.txt" },
			agentId: "test-agent",
			sessionId: "test-session",
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as ClassifyResponse;
		expect(body.decision).toBe("auto_approve");
		expect(body.category).toBe("read");
		expect(body.manifestId).toBeTruthy();
	});

	it("returns confirm for write-classified tools", async () => {
		const res = await postClassify(app, {
			tool: "write_file",
			params: { path: "/tmp/test.txt", content: "hello" },
			agentId: "test-agent",
			sessionId: "test-session",
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as ClassifyResponse;
		expect(body.decision).toBe("confirm");
		expect(body.category).toBe("write");
	});

	it("returns confirm for dangerous-classified tools", async () => {
		// python3 -c is classified as dangerous (interpreter inline exec)
		const res = await postClassify(app, {
			tool: "bash",
			params: { command: "python3 -c 'print(1)'" },
			agentId: "test-agent",
			sessionId: "test-session",
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as ClassifyResponse;
		expect(body.decision).toBe("confirm");
		expect(body.category).toBe("dangerous");
	});

	it("returns 400 for invalid request body", async () => {
		const res = await postClassify(app, {
			tool: "",
			params: {},
			agentId: "test-agent",
			sessionId: "test-session",
		});
		expect(res.status).toBe(400);
	});

	it("returns 400 when required fields are missing", async () => {
		const res = await postClassify(app, { tool: "bash" });
		expect(res.status).toBe(400);
	});

	it("includes source in audit entry when provided", async () => {
		await postClassify(app, {
			tool: "read_file",
			params: { path: "/tmp/test.txt" },
			agentId: "test-agent",
			sessionId: "test-session",
			source: "openclaw",
		});
		const entries = auditLogger.getRecent(1);
		expect(entries.length).toBe(1);
		expect(entries[0].source).toBe("openclaw");
	});

	it("creates audit entry for each classification", async () => {
		await postClassify(app, {
			tool: "read_file",
			params: { path: "/tmp/test.txt" },
			agentId: "test-agent",
			sessionId: "test-session",
		});
		const entries = auditLogger.getRecent(10);
		expect(entries.length).toBe(1);
		expect(entries[0].tool).toBe("read_file");
	});

	it("returns correct manifestId in response", async () => {
		const res = await postClassify(app, {
			tool: "read_file",
			params: { path: "/tmp/test.txt" },
			agentId: "test-agent",
			sessionId: "test-session",
		});
		const body = (await res.json()) as ClassifyResponse;
		expect(body.manifestId).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
		);
	});
});
