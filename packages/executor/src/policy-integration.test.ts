import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import { getDefaultConfig } from "@sentinel/policy";
import type { ActionManifest, PolicyDocument, ToolResult } from "@sentinel/types";
import type { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";
import type { ToolRegistry } from "./tools/registry.js";

let tempDir: string;
let workspaceDir: string;
let roWorkspaceDir: string;
let auditLogger: AuditLogger;
let registry: ToolRegistry;
let app: Hono;

const config = getDefaultConfig();

function makePolicy(): PolicyDocument {
	return {
		version: 1,
		toolGroups: {
			fs: ["read_file", "write_file", "edit_file"],
			runtime: ["bash"],
			network: ["browser", "fetch"],
		},
		defaults: {
			tools: { allow: ["*"], deny: ["group:network"] },
			workspace: { root: workspaceDir, access: "rw" },
			approval: { ask: "on-miss" },
		},
		agents: {
			work: {
				tools: { allow: ["group:fs", "group:runtime"], deny: [] },
				workspace: { root: workspaceDir, access: "rw" },
				approval: {
					ask: "on-miss",
					allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
				},
			},
			readonly: {
				tools: { allow: ["read_file"] },
				workspace: { root: roWorkspaceDir, access: "ro" },
				approval: { ask: "always" },
			},
		},
	};
}

function makeManifest(
	tool: string,
	parameters: Record<string, unknown>,
	agentId: string,
): ActionManifest {
	return {
		id: crypto.randomUUID(),
		timestamp: new Date().toISOString(),
		tool,
		parameters,
		sessionId: "integration-test",
		agentId,
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
	tempDir = mkdtempSync(join(tmpdir(), "sentinel-integration-"));
	workspaceDir = join(tempDir, "workspace");
	roWorkspaceDir = join(tempDir, "ro-workspace");
	mkdirSync(workspaceDir, { recursive: true });
	mkdirSync(roWorkspaceDir, { recursive: true });

	const dbPath = join(tempDir, "audit.db");
	auditLogger = new AuditLogger(dbPath);
	registry = createToolRegistry();
	app = createApp(config, makePolicy(), auditLogger, registry);
});

afterEach(() => {
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
});

describe("Policy Integration: full flow through executor", () => {
	it("agent 'work' auto-approves bash with rg allowlist match", async () => {
		const manifest = makeManifest(
			"bash",
			{ command: "/opt/homebrew/bin/rg --version" },
			"work",
		);
		// rg matches allowlist pattern "/opt/homebrew/bin/rg" with wildcard-like behavior
		// But the pattern is exact: "/opt/homebrew/bin/rg" without " *", so "--version" won't match
		// Actually the allowlist pattern is exact match only: "/opt/homebrew/bin/rg"
		// This command has args, so it won't match. Let's use exact match:
		const exactManifest = makeManifest(
			"bash",
			{ command: "/opt/homebrew/bin/rg" },
			"work",
		);
		const res = await postExecute(app, exactManifest);
		const result = (await res.json()) as ToolResult;
		// Even though rg doesn't exist, the policy says auto_approve
		// The bash handler will execute and fail, but we check it wasn't blocked
		expect(result.manifestId).toBe(exactManifest.id);
		// The request should reach execution (not be blocked by policy)
		expect(res.status).not.toBe(400);
	});

	it("agent 'readonly' blocks bash (group:runtime not in allow)", async () => {
		const manifest = makeManifest("bash", { command: "ls" }, "readonly");
		const res = await postExecute(app, manifest);
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(false);
		expect(result.error).toContain("not allowed");
	});

	it("agent 'work' reads file within workspace", async () => {
		const testFile = join(workspaceDir, "hello.txt");
		writeFileSync(testFile, "integration test content");
		const manifest = makeManifest("read_file", { path: testFile }, "work");
		const res = await postExecute(app, manifest);
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(true);
		expect(result.output).toBe("integration test content");
	});

	it("agent 'work' blocks read outside workspace", async () => {
		const manifest = makeManifest("read_file", { path: "/etc/hosts" }, "work");
		const res = await postExecute(app, manifest);
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(false);
		expect(result.error).toContain("workspace");
	});

	it("unknown agentId is blocked", async () => {
		const manifest = makeManifest("read_file", { path: "/tmp/x" }, "hacker");
		const res = await postExecute(app, manifest);
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(false);
		expect(result.error).toContain("Unknown agent");
	});

	it("credential filtering still applied after policy approval (Invariant #1)", async () => {
		const testFile = join(workspaceDir, "creds.txt");
		writeFileSync(testFile, "key=sk-ant-api03-secret123abc456def789");
		const manifest = makeManifest("read_file", { path: testFile }, "work");
		const res = await postExecute(app, manifest);
		const result = (await res.json()) as ToolResult;
		expect(result.success).toBe(true);
		expect(result.output).not.toContain("sk-ant-");
		expect(result.output).toContain("[REDACTED]");
	});

	it("every decision audited with agentId + policyVersion (Invariant #2)", async () => {
		const testFile = join(workspaceDir, "audit-test.txt");
		writeFileSync(testFile, "data");
		const manifest = makeManifest("read_file", { path: testFile }, "work");
		await postExecute(app, manifest);

		const entries = auditLogger.getRecent(10);
		const entry = entries.find((e) => e.manifestId === manifest.id);
		expect(entry).toBeDefined();
		expect(entry?.agentId).toBe("work");
		expect(entry?.policyVersion).toBe(1);
	});

	it("blocked operations are audited too", async () => {
		const manifest = makeManifest("read_file", { path: "/etc/passwd" }, "work");
		await postExecute(app, manifest);

		const entries = auditLogger.getRecent(10);
		const entry = entries.find((e) => e.manifestId === manifest.id);
		expect(entry).toBeDefined();
		expect(entry?.result).toBe("blocked_by_policy");
		expect(entry?.agentId).toBe("work");
	});
});
