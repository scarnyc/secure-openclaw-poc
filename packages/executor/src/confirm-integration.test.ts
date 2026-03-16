import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import type { SentinelConfig } from "@sentinel/types";
import type { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
		{ tool: "bash", defaultCategory: "dangerous" },
		{ tool: "read_file", defaultCategory: "read" },
	],
	autoApproveReadOps: true,
	auditLogPath: "",
	vaultPath: "",
	gwsDefaultDeny: false,
	llm: { provider: "anthropic", model: "claude-sonnet-4-20250514", maxTokens: 4096 },
};

function postConfirmOnly(hono: Hono, body: Record<string, unknown>) {
	return hono.request("/confirm-only", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-confirm-integ-")));
	process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
	auditLogger = new AuditLogger(join(tempDir, "audit.db"));
	registry = createToolRegistry();
	app = createApp(DEFAULT_CONFIG, auditLogger, registry).app;
});

afterEach(() => {
	vi.useRealTimers();
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
	delete process.env.SENTINEL_ALLOWED_ROOTS;
});

describe("Integration: /confirm-only full confirmation flow", () => {
	it("blocks until web page approve, then returns approved", async () => {
		// Start the /confirm-only request — it will block waiting for confirmation
		const confirmPromise = postConfirmOnly(app, {
			tool: "bash",
			params: { command: "rm -rf /" },
			agentId: "test-agent",
			sessionId: "test-session",
		});

		// Give server a tick to register the pending confirmation
		await new Promise((r) => setTimeout(r, 50));

		// Find the pending confirmation to get the manifestId
		const pendingRes = await app.request("/pending-confirmations");
		const pending = (await pendingRes.json()) as Array<{
			manifestId: string;
			tool: string;
			category: string;
		}>;
		expect(pending.length).toBe(1);
		expect(pending[0].tool).toBe("bash");

		const manifestId = pending[0].manifestId;

		// Approve via web endpoint
		const approveRes = await app.request(`/confirm/${manifestId}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ approved: true }),
		});
		expect(approveRes.status).toBe(200);

		// /confirm-only should now resolve with approved
		const res = await confirmPromise;
		expect(res.status).toBe(200);
		const body = (await res.json()) as { decision: string; category: string; manifestId: string };
		expect(body.decision).toBe("approved");
		expect(body.manifestId).toBe(manifestId);

		// Pending confirmations should be empty
		const afterRes = await app.request("/pending-confirmations");
		const afterPending = (await afterRes.json()) as Array<unknown>;
		expect(afterPending.length).toBe(0);
	});

	it("auto-denies after 5-minute timeout when no approval received", async () => {
		vi.useFakeTimers();

		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

		// Start the /confirm-only request
		const confirmPromise = postConfirmOnly(app, {
			tool: "bash",
			params: { command: "rm -rf /" },
			agentId: "test-agent",
			sessionId: "test-session",
		});

		// Give server a tick to register the pending confirmation
		await vi.advanceTimersByTimeAsync(50);

		// Verify it's pending
		const pendingRes = await app.request("/pending-confirmations");
		const pending = (await pendingRes.json()) as Array<{ manifestId: string }>;
		expect(pending.length).toBe(1);

		// Advance past the 5-minute timeout (300_000ms)
		await vi.advanceTimersByTimeAsync(300_000);

		// /confirm-only should resolve with denied
		const res = await confirmPromise;
		expect(res.status).toBe(200);
		const body = (await res.json()) as { decision: string; category: string };
		expect(body.decision).toBe("denied");

		// Pending confirmations should be cleared
		const afterRes = await app.request("/pending-confirmations");
		const afterPending = (await afterRes.json()) as Array<unknown>;
		expect(afterPending.length).toBe(0);

		warnSpy.mockRestore();
	});
});
