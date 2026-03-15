import type { AuditLogger } from "@sentinel/audit";
import type { CredentialVault } from "@sentinel/crypto";
import { LoopGuard, RateLimiter } from "@sentinel/policy";
import type {
	ActionManifest,
	AgentCard,
	EgressBinding,
	PolicyDecision,
	SentinelConfig,
} from "@sentinel/types";
import { redactAll } from "@sentinel/types";
import { Hono } from "hono";
import { z } from "zod";
import { createAuthMiddleware } from "./auth-middleware.js";
import { type ClassifyGuards, handleClassify } from "./classify-endpoint.js";
import { handleConfirmOnly } from "./confirm-endpoint.js";
import type { DelegationQueue } from "./delegate-handler.js";
import { createEgressProxyHandler } from "./egress-proxy.js";
import { handleFilterOutput } from "./filter-endpoint.js";
import { createLlmProxyHandler } from "./llm-proxy.js";
import { requestIdMiddleware } from "./request-id.js";
import { createResponseSigner } from "./response-signer.js";
import {
	type ConfirmFn,
	handleExecute,
	ManifestValidationError,
	type PipelineGuards,
} from "./router.js";
import type { TelegramConfirmAdapter } from "./telegram-confirm.js";
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
	delegationQueue?: DelegationQueue,
	egressBindings?: EgressBinding[],
	telegramAdapter?: TelegramConfirmAdapter,
): Hono {
	const app = new Hono();
	const pendingConfirmations = new Map<string, PendingConfirmation>();

	// SENTINEL: Shared confirmation resolver — used by both HTTP endpoint and Telegram adapter
	function resolveConfirmation(manifestId: string, approved: boolean): boolean {
		const pending = pendingConfirmations.get(manifestId);
		if (!pending) return false;
		pendingConfirmations.delete(manifestId);
		pending.resolve(approved);
		return true;
	}

	// SENTINEL: Wire Telegram adapter to resolve confirmations from callback queries
	if (telegramAdapter) {
		telegramAdapter.bindResolver(resolveConfirmation);
	}

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

			// SENTINEL: Fire-and-forget Telegram notification (fail-open — 5-min auto-deny still applies)
			if (telegramAdapter) {
				telegramAdapter
					.sendConfirmation({
						manifestId: manifest.id,
						tool: manifest.tool,
						parameters: manifest.parameters,
						category: decision.category,
						reason: decision.reason,
					})
					.catch((err) => {
						console.error(
							`[telegram] IMPORTANT: Failed to send confirmation for ${manifest.id} (${manifest.tool}, ${decision.category}). ` +
								`User will NOT receive Telegram prompt — action will auto-deny in ${CONFIRMATION_TIMEOUT_MS / 1000}s. ` +
								`Error: ${err instanceof Error ? err.message : "Unknown"}`,
						);
					});
			}
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
	app.use("/classify", createBodyLimitMiddleware(10 * 1024 * 1024, "10MB"));
	app.use("/filter-output", createBodyLimitMiddleware(10 * 1024 * 1024, "10MB"));
	app.use("/confirm-only", createBodyLimitMiddleware(10 * 1024 * 1024, "10MB"));
	// SENTINEL: I7 — 25MB for LLM proxy to accommodate large context windows (200K+ tokens)
	app.use("/proxy/llm/*", createBodyLimitMiddleware(25 * 1024 * 1024, "25MB"));
	app.use("/proxy/egress", createBodyLimitMiddleware(10 * 1024 * 1024, "10MB"));

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

	// SENTINEL: Wave 2.3 — classify-only endpoint for OpenClaw plugin (no execution)
	app.post("/classify", async (c) => {
		try {
			return await handleClassify(c, config, auditLogger, guards as ClassifyGuards);
		} catch (error) {
			console.error(
				`[classify] Unhandled error: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			return c.json({ error: "Internal classification error" }, 500);
		}
	});

	// SENTINEL: Wave 2.4 — classify + TUI confirmation without execution (for OpenClaw plugin)
	app.post("/confirm-only", async (c) => {
		try {
			return await handleConfirmOnly(c, config, auditLogger, guards as ClassifyGuards, confirmFn);
		} catch (error) {
			console.error(
				`[confirm-only] Unhandled error: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			return c.json({ error: "Internal confirmation error" }, 500);
		}
	});

	// SENTINEL: Wave 2.3 — output filtering endpoint for OpenClaw plugin
	app.post("/filter-output", async (c) => {
		try {
			return await handleFilterOutput(c);
		} catch (error) {
			console.error(
				`[filter-output] Unhandled error: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			return c.json({ error: "Internal filter error" }, 500);
		}
	});

	// SENTINEL: Wave 2.3 — delegation endpoints (only active when queue provided)
	if (delegationQueue) {
		app.get("/pending-delegations", (c) => {
			const pending = delegationQueue.getPending();
			// SENTINEL: Redact credential patterns from task strings (MEDIUM-3)
			const sanitized = pending.map((d) => ({
				...d,
				task: redactAll(d.task),
			}));
			return c.json(sanitized);
		});

		app.post("/delegation-status/:id", async (c) => {
			const { id } = c.req.param();
			// SENTINEL: Validate delegation status updates (HIGH-1 security fix)
			const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
			if (!uuidRegex.test(id)) {
				return c.json({ error: "Invalid delegation ID format" }, 400);
			}
			const raw = await c.req.json();
			const DelegationStatusSchema = z.object({
				status: z.enum(["running", "completed", "failed"]),
				prUrl: z.string().url().optional(),
			});
			const parsed = DelegationStatusSchema.safeParse(raw);
			if (!parsed.success) {
				return c.json({ error: `Invalid body: ${parsed.error.message}` }, 400);
			}
			delegationQueue.updateStatus(id, parsed.data.status, parsed.data.prUrl);

			// SENTINEL: Audit delegation status transitions (MEDIUM-4)
			auditLogger.log({
				id: crypto.randomUUID(),
				timestamp: new Date().toISOString(),
				manifestId: id,
				sessionId: "delegation",
				agentId: "system",
				tool: "delegate.code",
				category: "write",
				decision: "allow",
				parameters_summary: `status=${parsed.data.status}`,
				result: "success",
				duration_ms: 0,
				source: "sentinel",
			});

			return c.json({ ok: true });
		});
	}

	// SENTINEL: Vault-based key injection when available, env var fallback otherwise
	app.all("/proxy/llm/*", createLlmProxyHandler(vault, auditLogger));

	// SENTINEL: Wave 2.4 — egress proxy with domain-scoped credential injection
	if (egressBindings && egressBindings.length > 0) {
		app.post("/proxy/egress", createEgressProxyHandler(vault, auditLogger, egressBindings));
	}

	app.post("/execute", async (c) => {
		try {
			const body = await c.req.json();
			const result = await handleExecute(body, config, auditLogger, registry, confirmFn, guards);
			return c.json(result, result.success ? 200 : 422);
		} catch (error) {
			if (error instanceof ManifestValidationError) {
				return c.json({ error: error.message }, 400);
			}
			// SENTINEL: M7 — Best-effort audit for unhandled exceptions (Invariant #2)
			try {
				auditLogger.log({
					id: crypto.randomUUID(),
					timestamp: new Date().toISOString(),
					manifestId: "unknown",
					sessionId: "unknown",
					agentId: "unknown",
					tool: "unknown",
					category: "dangerous",
					decision: "allow",
					parameters_summary: "",
					result: "failure",
					duration_ms: 0,
				});
			} catch (auditErr) {
				console.error(
					`[execute] Audit logging failed: ${auditErr instanceof Error ? auditErr.message : "Unknown"}`,
				);
			}
			console.error(
				`[execute] Unhandled error: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			return c.json({ error: "Internal execution error" }, 500);
		}
	});

	app.post("/confirm/:manifestId", async (c) => {
		const { manifestId } = c.req.param();

		const raw = await c.req.json();
		const parsed = ConfirmBodySchema.safeParse(raw);
		if (!parsed.success) {
			return c.json({ error: "Invalid body: expected { approved: boolean }" }, 400);
		}

		const resolved = resolveConfirmation(manifestId, parsed.data.approved);
		if (!resolved) {
			return c.json({ error: "No pending confirmation found" }, 404);
		}

		return c.json({ status: parsed.data.approved ? "approved" : "denied" });
	});

	return app;
}
