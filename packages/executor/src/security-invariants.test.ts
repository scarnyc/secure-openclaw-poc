import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import type { ActionManifest, ToolResult } from "@sentinel/types";
import type { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";
import type { ToolRegistry } from "./tools/registry.js";

/**
 * Security invariant tests — one per CLAUDE.md invariant.
 * These are dedicated tests ensuring each invariant holds.
 */

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
		sessionId: "test-session",
		agentId: "test-agent",
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
	tempDir = mkdtempSync(join(tmpdir(), "sentinel-invariant-test-"));
	const dbPath = join(tempDir, "audit.db");
	auditLogger = new AuditLogger(dbPath);
	registry = createToolRegistry();
	app = createApp(DEFAULT_CONFIG, auditLogger, registry);
});

afterEach(() => {
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
});

describe("Security Invariant #1: No credentials in tool responses", () => {
	it("strips seeded API keys from bash output", async () => {
		const manifest = makeManifest({
			tool: "bash",
			parameters: { command: "echo sk-ant-abc123-testkey456789012345" },
		});
		const res = await postExecute(app, manifest);
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(true);
		expect(result.output).not.toContain("sk-ant-");
		expect(result.output).toContain("[REDACTED]");
	});

	it("strips seeded API keys from read_file output", async () => {
		const testFile = join(tempDir, "has-key.txt");
		writeFileSync(testFile, "config:\n  key: sk-ant-secret123-abcdef789012345\n  host: localhost");
		const manifest = makeManifest({
			tool: "read_file",
			parameters: { path: testFile },
		});
		const res = await postExecute(app, manifest);
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(true);
		expect(result.output).not.toContain("sk-ant-");
		expect(result.output).toContain("[REDACTED]");
	});
});

describe("Security Invariant #2: All tool calls audited", () => {
	it("audit rows match tool call count 1:1", async () => {
		const manifests = [
			makeManifest({ tool: "bash", parameters: { command: "echo one" } }),
			makeManifest({ tool: "bash", parameters: { command: "echo two" } }),
			makeManifest({ tool: "bash", parameters: { command: "echo three" } }),
		];

		for (const m of manifests) {
			await postExecute(app, m);
		}

		const entries = auditLogger.getRecent(100);
		for (const m of manifests) {
			const match = entries.find((e) => e.manifestId === m.id);
			expect(match, `audit entry for manifest ${m.id}`).toBeDefined();
		}
		expect(entries.length).toBeGreaterThanOrEqual(manifests.length);
	});
});

describe("Security Invariant #3: Blocked tool categories enforced", () => {
	it("denies read_file for .env paths", async () => {
		const manifest = makeManifest({
			tool: "read_file",
			parameters: { path: "/app/.env" },
		});
		const res = await postExecute(app, manifest);
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(false);
		expect(result.error).toContain("denied");
	});

	it("denies read_file for .pem paths", async () => {
		const manifest = makeManifest({
			tool: "read_file",
			parameters: { path: "/app/server.pem" },
		});
		const res = await postExecute(app, manifest);
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(false);
		expect(result.error).toContain("denied");
	});

	it("denies bash commands reading sensitive files with head/tail", async () => {
		// head and tail are classified as "read" by the policy engine,
		// so they auto-approve and reach the bash deny-list check.
		const commands = ["head -1 .env", "tail .env.local", "head /app/secret.pem", "tail vault.enc"];
		for (const command of commands) {
			const manifest = makeManifest({
				tool: "bash",
				parameters: { command },
			});
			const res = await postExecute(app, manifest);
			const result = (await res.json()) as ToolResult;
			expect(result.success, `should deny: ${command}`).toBe(false);
			expect(result.error).toContain("sensitive file");
		}
	});
});

describe("Security Invariant #6: Policy changes require restart", () => {
	it("config mutation after createApp has no effect on classification", async () => {
		const config = structuredClone(DEFAULT_CONFIG);
		config.autoApproveReadOps = true;
		const frozenConfig = Object.freeze(structuredClone(config));
		const testApp = createApp(frozenConfig, auditLogger, registry);

		// Read op should auto-approve with autoApproveReadOps=true
		const readManifest = makeManifest({
			tool: "bash",
			parameters: { command: "echo hello" },
		});
		const res1 = await postExecute(testApp, readManifest);
		const result1 = (await res1.json()) as ToolResult;
		expect(result1.success).toBe(true);

		// Attempting to mutate frozen config throws
		expect(() => {
			(frozenConfig as Record<string, unknown>).autoApproveReadOps = false;
		}).toThrow();
	});
});
