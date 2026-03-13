import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import type { FilterOutputResponse, SentinelConfig } from "@sentinel/types";
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
	classifications: [],
	autoApproveReadOps: true,
	auditLogPath: "",
	vaultPath: "",
	gwsDefaultDeny: false,
	llm: { provider: "anthropic", model: "claude-sonnet-4-20250514", maxTokens: 4096 },
};

async function postFilter(app: Hono, body: Record<string, unknown>): Promise<Response> {
	return app.request("/filter-output", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-filter-test-")));
	const dbPath = join(tempDir, "audit.db");
	auditLogger = new AuditLogger(dbPath);
	registry = createToolRegistry();
	app = createApp(DEFAULT_CONFIG, auditLogger, registry);
});

afterEach(() => {
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
});

describe("POST /filter-output", () => {
	it("passes through clean output unchanged", async () => {
		const res = await postFilter(app, {
			output: "Hello, world!",
			agentId: "test-agent",
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as FilterOutputResponse;
		expect(body.filtered).toBe("Hello, world!");
		expect(body.redacted).toBe(false);
		expect(body.moderationFlagged).toBe(false);
		expect(body.moderationBlocked).toBe(false);
	});

	it("redacts API keys from output", async () => {
		const key = ["sk", "ant", "api03", "abc123def456"].join("-");
		const res = await postFilter(app, {
			output: `The key is ${key}`,
			agentId: "test-agent",
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as FilterOutputResponse;
		expect(body.filtered).not.toContain("sk-ant");
		expect(body.redacted).toBe(true);
	});

	it("scrubs PII patterns from output", async () => {
		const res = await postFilter(app, {
			output: "SSN: 123-45-6789",
			agentId: "test-agent",
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as FilterOutputResponse;
		expect(body.filtered).not.toContain("123-45-6789");
		expect(body.redacted).toBe(true);
	});

	it("returns 400 for invalid request", async () => {
		const res = await postFilter(app, { agentId: "test" });
		expect(res.status).toBe(400);
	});

	it("returns 400 when output field is missing", async () => {
		const res = await postFilter(app, {});
		expect(res.status).toBe(400);
	});

	it("handles empty output string", async () => {
		const res = await postFilter(app, {
			output: "",
			agentId: "test-agent",
		});
		// Empty string fails z.string() min(1) implicitly — but our schema doesn't have min(1) for output
		// So it should pass
		expect(res.status).toBe(200);
		const body = (await res.json()) as FilterOutputResponse;
		expect(body.filtered).toBe("");
		expect(body.redacted).toBe(false);
	});
});
