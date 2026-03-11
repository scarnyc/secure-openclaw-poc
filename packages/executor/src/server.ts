import type { AuditLogger } from "@sentinel/audit";
import type { CredentialVault } from "@sentinel/crypto";
import { LoopGuard, RateLimiter } from "@sentinel/policy";
import type { ActionManifest, AgentCard, PolicyDecision, SentinelConfig } from "@sentinel/types";
import { Hono } from "hono";
import { z } from "zod";
import { createAuthMiddleware } from "./auth-middleware.js";
import { createLlmProxyHandler } from "./llm-proxy.js";
import { requestIdMiddleware } from "./request-id.js";
import {
	type ConfirmFn,
	handleExecute,
	ManifestValidationError,
	type PipelineGuards,
} from "./router.js";
import type { ToolRegistry } from "./tools/registry.js";

const ConfirmBodySchema = z.object({
	approved: z.boolean(),
});

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
	vault?: CredentialVault,
): Hono {
	const app = new Hono();
	const pendingConfirmations = new Map<string, PendingConfirmation>();

	// SENTINEL: Phase 1 pipeline guards — rate limiter and loop guard
	const guards: PipelineGuards = {
		rateLimiter: new RateLimiter({ rate: 60, period: 60_000 }), // 60 req/min per agent
		loopGuard: new LoopGuard(),
	};

	const confirmFn: ConfirmFn = (manifest, decision) => {
		return new Promise<boolean>((resolve) => {
			pendingConfirmations.set(manifest.id, { manifest, decision, resolve });
			// The caller (POST /execute) will wait; POST /confirm/:id resolves it
		});
	};

	// SENTINEL: request UUID for structured correlation logging (Phase 1)
	app.use("*", requestIdMiddleware);

	app.get("/health", (c) => {
		return c.json({ status: "ok", version: "0.1.0" });
	});

	// Auth middleware for all routes except /health
	// SENTINEL: constant-time bearer token auth (Phase 1 hardening)
	const authMiddleware = createAuthMiddleware(config.authToken);
	if (!config.authToken) {
		console.warn(
			"[sentinel] WARNING: No authToken configured — executor running without authentication",
		);
	}
	app.use("*", async (c, next) => {
		if (c.req.path === "/health") {
			return next();
		}
		return authMiddleware(c, next);
	});

	app.get("/agent-card", (c) => {
		return c.json(AGENT_CARD);
	});

	app.get("/tools", (c) => {
		return c.json(registry.list());
	});

	app.get("/pending-confirmations", (c) => {
		const pending = Array.from(pendingConfirmations.entries()).map(([id, p]) => ({
			manifestId: id,
			tool: p.manifest.tool,
			parameters: p.manifest.parameters,
			category: p.decision.category,
			reason: p.decision.reason,
		}));
		return c.json(pending);
	});

	// SENTINEL: Vault-based key injection when available, env var fallback otherwise
	app.all("/proxy/llm/*", createLlmProxyHandler(vault));

	app.post("/execute", async (c) => {
		try {
			const body = await c.req.json();
			const result = await handleExecute(body, config, auditLogger, registry, confirmFn, guards);
			return c.json(result, result.success ? 200 : 422);
		} catch (error) {
			if (error instanceof ManifestValidationError) {
				return c.json({ error: error.message }, 400);
			}
			console.error(
				`[execute] Unhandled error: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			return c.json({ error: "Internal execution error" }, 500);
		}
	});

	app.post("/confirm/:manifestId", async (c) => {
		const { manifestId } = c.req.param();
		const pending = pendingConfirmations.get(manifestId);

		if (!pending) {
			return c.json({ error: "No pending confirmation found" }, 404);
		}

		const raw = await c.req.json();
		const parsed = ConfirmBodySchema.safeParse(raw);
		if (!parsed.success) {
			return c.json({ error: "Invalid body: expected { approved: boolean }" }, 400);
		}
		const approved = parsed.data.approved;

		pendingConfirmations.delete(manifestId);
		pending.resolve(approved);

		return c.json({ status: approved ? "approved" : "denied" });
	});

	return app;
}
