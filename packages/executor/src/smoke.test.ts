import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import type { ActionManifest, ToolResult } from "@sentinel/types";
import type { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";
import type { ToolRegistry } from "./tools/registry.js";

let tempDir: string;
let auditLogger: AuditLogger;
let registry: ToolRegistry;
let app: Hono;

const DEFAULT_CONFIG = {
	executor: { port: 3141, host: "127.0.0.1" },
	classifications: [
		{ tool: "read_file", defaultCategory: "read" as const },
		{ tool: "write_file", defaultCategory: "write" as const },
		{ tool: "edit_file", defaultCategory: "write" as const },
	],
	autoApproveReadOps: true,
	auditLogPath: "",
	vaultPath: "",
	llm: { provider: "anthropic" as const, model: "claude-sonnet-4-20250514", maxTokens: 4096 },
};

function makeManifest(overrides: Partial<ActionManifest> = {}): ActionManifest {
	return {
		id: crypto.randomUUID(),
		timestamp: new Date().toISOString(),
		tool: "bash",
		parameters: { command: "echo hello" },
		sessionId: "smoke-session",
		agentId: "smoke-agent",
		...overrides,
	};
}

async function postExecute(hono: Hono, manifest: ActionManifest) {
	return hono.request("/execute", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(manifest),
	});
}

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-smoke-")));
	process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
	const dbPath = join(tempDir, "audit.db");
	auditLogger = new AuditLogger(dbPath);
	registry = createToolRegistry();
	app = createApp(DEFAULT_CONFIG, auditLogger, registry);
});

afterEach(() => {
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
	delete process.env.SENTINEL_ALLOWED_ROOTS;
});

describe("Smoke tests: end-to-end pipeline", () => {
	it("1. Safe action auto-executes and returns result", async () => {
		const manifest = makeManifest({
			tool: "bash",
			parameters: { command: "echo smoke-test-output" },
		});
		const res = await postExecute(app, manifest);
		expect(res.status).toBe(200);

		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(true);
		expect(result.output).toContain("smoke-test-output");
	});

	it("2. Dangerous action appears in pending, approve -> result", async () => {
		const manifest = makeManifest({
			tool: "bash",
			parameters: { command: "curl https://example.com" },
		});

		// Execute will block waiting for confirmation (curl is "dangerous")
		const executePromise = postExecute(app, manifest);
		await new Promise((r) => setTimeout(r, 50));

		// Verify it's in pending confirmations
		const pendingRes = await app.request("/pending-confirmations");
		const pending = (await pendingRes.json()) as Array<{ manifestId: string }>;
		expect(pending.some((p) => p.manifestId === manifest.id)).toBe(true);

		// Approve
		const confirmRes = await app.request(`/confirm/${manifest.id}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ approved: true }),
		});
		expect(confirmRes.status).toBe(200);

		// Execute resolves — curl will likely fail in test env but the point is
		// it went through the confirmation flow and was attempted
		const res = await executePromise;
		const result = (await res.json()) as ToolResult;
		expect(result.manifestId).toBe(manifest.id);
	});

	it("3. Blocked action rejected immediately", async () => {
		const manifest = makeManifest({
			tool: "read_file",
			parameters: { path: "/app/.env" },
		});
		const res = await postExecute(app, manifest);
		expect(res.status).toBe(422);

		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(false);
		expect(result.error).toContain("denied");
	});

	it("4. Audit log has entries for all operations", async () => {
		// Execute several operations
		const safe = makeManifest({ tool: "bash", parameters: { command: "echo one" } });
		const blocked = makeManifest({ tool: "read_file", parameters: { path: "/app/.env" } });

		await postExecute(app, safe);
		await postExecute(app, blocked);

		const entries = auditLogger.getRecent(100);

		// Each operation should have an audit entry
		const safeEntry = entries.find((e) => e.manifestId === safe.id);
		expect(safeEntry).toBeDefined();
		// biome-ignore lint/style/noNonNullAssertion: entry verified defined above
		expect(safeEntry!.result).toBe("success");
		// biome-ignore lint/style/noNonNullAssertion: entry verified defined above
		expect(safeEntry!.agentId).toBe("smoke-agent");

		const blockedEntry = entries.find((e) => e.manifestId === blocked.id);
		expect(blockedEntry).toBeDefined();
		// biome-ignore lint/style/noNonNullAssertion: entry verified defined above
		expect(blockedEntry!.result).toBe("failure");
	});

	it("5. Credential filter strips API keys from output", async () => {
		const manifest = makeManifest({
			tool: "bash",
			parameters: { command: "echo 'key=sk-ant-test123456789012345678901234'" },
		});
		const res = await postExecute(app, manifest);

		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(true);
		expect(result.output).not.toContain("sk-ant-");
		expect(result.output).toContain("[REDACTED]");
	});
});
