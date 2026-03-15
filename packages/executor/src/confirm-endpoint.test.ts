import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import type { SentinelConfig } from "@sentinel/types";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ClassifyGuards } from "./classify-endpoint.js";
import { handleConfirmOnly } from "./confirm-endpoint.js";
import type { ConfirmFn } from "./router.js";

let tempDir: string;
let auditLogger: AuditLogger;

const DEFAULT_CONFIG: SentinelConfig = {
	executor: { port: 3141, host: "127.0.0.1" },
	classifications: [
		{ tool: "file.read", defaultCategory: "read" },
		{ tool: "file.write", defaultCategory: "write" },
		{ tool: "bash", defaultCategory: "dangerous" },
	],
	autoApproveReadOps: true,
	auditLogPath: "",
	vaultPath: "",
	gwsDefaultDeny: false,
	llm: { provider: "anthropic", model: "claude-sonnet-4-20250514", maxTokens: 4096 },
};

function createTestApp(overrides?: { confirmFn?: ConfirmFn }) {
	const guards: ClassifyGuards = {
		rateLimiter: undefined,
		loopGuard: undefined,
	};
	const confirmFn: ConfirmFn =
		overrides?.confirmFn ?? (vi.fn().mockResolvedValue(true) as unknown as ConfirmFn);

	const app = new Hono();
	app.post("/confirm-only", async (c) => {
		return handleConfirmOnly(c, DEFAULT_CONFIG, auditLogger, guards, confirmFn);
	});

	return { app, confirmFn };
}

async function postConfirm(app: Hono, body: Record<string, unknown>): Promise<Response> {
	return app.request("/confirm-only", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-confirm-test-")));
	const dbPath = join(tempDir, "audit.db");
	auditLogger = new AuditLogger(dbPath);
});

afterEach(() => {
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
});

describe("POST /confirm-only", () => {
	it("returns 400 for invalid body", async () => {
		const { app } = createTestApp();
		const res = await postConfirm(app, {});
		expect(res.status).toBe(400);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.error).toBeDefined();
	});

	it("returns 200 auto_approve for read-classified tool", async () => {
		const { app } = createTestApp();
		const res = await postConfirm(app, {
			tool: "file.read",
			params: { path: "/tmp/x" },
			agentId: "a1",
			sessionId: "s1",
		});
		expect(res.status).toBe(200);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.decision).toBe("auto_approve");
		expect(json.category).toBe("read");
	});

	it("audits the classification", async () => {
		const { app } = createTestApp();
		const logSpy = vi.spyOn(auditLogger, "log");
		await postConfirm(app, {
			tool: "file.read",
			params: { path: "/tmp/x" },
			agentId: "a1",
			sessionId: "s1",
		});
		expect(logSpy).toHaveBeenCalledWith(expect.objectContaining({ tool: "file.read" }));
	});

	it("returns approved when confirmFn returns true", async () => {
		const mockConfirm = vi.fn().mockResolvedValue(true) as unknown as ConfirmFn;
		const { app } = createTestApp({ confirmFn: mockConfirm });
		// "bash" is classified as "dangerous" → maps to "confirm" action
		const res = await postConfirm(app, {
			tool: "bash",
			params: { command: "rm -rf /" },
			agentId: "a1",
			sessionId: "s1",
		});
		expect(res.status).toBe(200);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.decision).toBe("approved");
	});

	it("returns denied when confirmFn returns false", async () => {
		const mockConfirm = vi.fn().mockResolvedValue(false) as unknown as ConfirmFn;
		const { app } = createTestApp({ confirmFn: mockConfirm });
		const res = await postConfirm(app, {
			tool: "bash",
			params: { command: "rm -rf /" },
			agentId: "a1",
			sessionId: "s1",
		});
		expect(res.status).toBe(200);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.decision).toBe("denied");
	});
});
