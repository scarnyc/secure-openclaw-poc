import type { AuditLogger } from "@sentinel/audit";
import type { CredentialVault } from "@sentinel/crypto";
import { LoopGuard, RateLimiter } from "@sentinel/policy";
import type { ActionManifest, AgentCard, PolicyDecision, SentinelConfig } from "@sentinel/types";
import { Hono } from "hono";
import { z } from "zod";
import { createAuthMiddleware } from "./auth-middleware.js";
import { createLlmProxyHandler } from "./llm-proxy.js";
import { requestIdMiddleware } from "./request-id.js";
import { createResponseSigner } from "./response-signer.js";
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
	hmacSecret?: Buffer,
): Hono {
	const app = new Hono();
	const pendingConfirmations = new Map<string, PendingConfirmation>();

	// SENTINEL: Phase 1 pipeline guards — rate limiter and loop guard
	const guards: PipelineGuards = {
		rateLimiter: new RateLimiter({ rate: 60, period: 60_000 }), // 60 req/min per agent
		loopGuard: new LoopGuard(),
	};

	// SENTINEL: 5-minute auto-deny for unresolved confirmations (LOW-12)
	const CONFIRMATION_TIMEOUT_MS = 300_000;

	const confirmFn: ConfirmFn = (manifest, decision) => {
		return new Promise<boolean>((resolve) => {
			const timeout = setTimeout(() => {
				pendingConfirmations.delete(manifest.id);
				resolve(false); // auto-deny
				console.warn(
					`[sentinel] Confirmation timeout for ${manifest.id} (${manifest.tool}) — auto-denied after ${CONFIRMATION_TIMEOUT_MS / 1000}s`,
				);
			}, CONFIRMATION_TIMEOUT_MS);

			pendingConfirmations.set(manifest.id, {
				manifest,
				decision,
				resolve: (approved: boolean) => {
					clearTimeout(timeout);
					resolve(approved);
				},
			});
		});
	};

	// SENTINEL: request UUID for structured correlation logging (Phase 1)
	app.use("*", requestIdMiddleware);

	// SENTINEL: Body size limits (LOW-17) — defense-in-depth against DoS
	// Two-layer enforcement: (1) Content-Length header check for early rejection,
	// (2) actual body size verification after reading to catch chunked transfer bypass.
	// Docker mode additionally requires Content-Length to be present.
	const createBodyLimitMiddleware = (maxBytes: number, label: string) => {
		return async (c: import("hono").Context, next: import("hono").Next) => {
			const isBodyMethod =
				c.req.method === "POST" || c.req.method === "PUT" || c.req.method === "PATCH";
			const contentLength = c.req.header("content-length");

			// Layer 1: reject early if Content-Length exceeds limit
			if (contentLength) {
				if (Number.parseInt(contentLength, 10) > maxBytes) {
					return c.json({ error: `Request body too large (max ${label})` }, 413);
				}
			} else if (process.env.SENTINEL_DOCKER === "true" && isBodyMethod) {
				// In Docker: require Content-Length to prevent chunked transfer bypass
				return c.json({ error: "Content-Length header required" }, 411);
			}

			// Layer 2: verify actual body size for requests without Content-Length
			// (catches chunked transfer encoding bypass in non-Docker mode)
			if (isBodyMethod && !contentLength) {
				const body = await c.req.raw.clone().arrayBuffer();
				if (body.byteLength > maxBytes) {
					return c.json({ error: `Request body too large (max ${label})` }, 413);
				}
			}

			return next();
		};
	};
	app.use("/execute", createBodyLimitMiddleware(10 * 1024 * 1024, "10MB"));
	app.use("/proxy/llm/*", createBodyLimitMiddleware(100 * 1024 * 1024, "100MB"));

	// SENTINEL: HMAC-SHA256 response signing for integrity verification (B4)
	// Placed before routes so all responses (including /health) get signed
	if (hmacSecret) {
		app.use("*", createResponseSigner(hmacSecret));
	}

	app.get("/health", (c) => {
		return c.json({ status: "ok", version: "0.1.0" });
	});

	// Auth middleware for all routes except /health
	// SENTINEL: constant-time bearer token auth (Phase 1 hardening)
	const authMiddleware = createAuthMiddleware(config.authToken);
	if (!config.authToken) {
		if (process.env.SENTINEL_DOCKER === "true") {
			throw new Error(
				"[sentinel] FATAL: Docker mode without auth token — refusing to start unauthenticated",
			);
		} else {
			console.warn(
				"[sentinel] WARNING: No authToken configured — running without authentication (local dev)",
			);
		}
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
