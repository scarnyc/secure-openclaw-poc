import type { AuditLogger } from "@sentinel/audit";
import type { ActionManifest, AgentCard, PolicyDecision, SentinelConfig } from "@sentinel/types";
import { Hono } from "hono";
import { type ConfirmFn, handleExecute, ManifestValidationError } from "./router.js";
import type { ToolRegistry } from "./tools/registry.js";

interface PendingConfirmation {
	manifest: ActionManifest;
	decision: PolicyDecision;
	resolve: (approved: boolean) => void;
}

const AGENT_CARD: AgentCard = {
	name: "Sentinel Executor",
	description: "Trusted tool execution server for the Sentinel agent runtime",
	url: "http://127.0.0.1:3141",
	capabilities: [
		{
			name: "tool-execution",
			description: "Execute tools with policy enforcement and audit logging",
		},
	],
	version: "0.1.0",
};

export function createApp(
	config: SentinelConfig,
	auditLogger: AuditLogger,
	registry: ToolRegistry,
): Hono {
	const app = new Hono();
	const pendingConfirmations = new Map<string, PendingConfirmation>();

	const confirmFn: ConfirmFn = (manifest, decision) => {
		return new Promise<boolean>((resolve) => {
			pendingConfirmations.set(manifest.id, { manifest, decision, resolve });
			// The caller (POST /execute) will wait; POST /confirm/:id resolves it
		});
	};

	app.get("/health", (c) => {
		return c.json({ status: "ok", version: "0.1.0" });
	});

	app.get("/agent-card", (c) => {
		return c.json(AGENT_CARD);
	});

	app.get("/tools", (c) => {
		return c.json(registry.list());
	});

	app.post("/execute", async (c) => {
		try {
			const body = await c.req.json();
			const result = await handleExecute(body, config, auditLogger, registry, confirmFn);
			return c.json(result, result.success ? 200 : 200);
		} catch (error) {
			if (error instanceof ManifestValidationError) {
				return c.json({ error: error.message }, 400);
			}
			return c.json({ error: error instanceof Error ? error.message : "Internal error" }, 500);
		}
	});

	app.post("/confirm/:manifestId", async (c) => {
		const { manifestId } = c.req.param();
		const pending = pendingConfirmations.get(manifestId);

		if (!pending) {
			return c.json({ error: "No pending confirmation found" }, 404);
		}

		const body = await c.req.json();
		const approved = body.approved === true;

		pendingConfirmations.delete(manifestId);
		pending.resolve(approved);

		return c.json({ status: approved ? "approved" : "denied" });
	});

	return app;
}
