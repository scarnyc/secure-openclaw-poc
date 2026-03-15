import type { AuditLogger } from "@sentinel/audit";
import { classify } from "@sentinel/policy";
import type { SentinelConfig } from "@sentinel/types";
import { ActionManifestSchema, ClassifyRequestSchema } from "@sentinel/types";
import type { Context } from "hono";
import type { ClassifyGuards } from "./classify-endpoint.js";
import type { ConfirmFn } from "./router.js";

export async function handleConfirmOnly(
	c: Context,
	config: SentinelConfig,
	auditLogger: AuditLogger,
	guards: ClassifyGuards,
	confirmFn: ConfirmFn,
): Promise<Response> {
	const raw = await c.req.json();
	const parsed = ClassifyRequestSchema.safeParse(raw);
	if (!parsed.success) {
		return c.json({ error: `Invalid request: ${parsed.error.message}` }, 400);
	}

	const { tool, params, agentId, sessionId, source } = parsed.data;

	// Build an ActionManifest from the classify request
	const manifest = ActionManifestSchema.parse({
		tool,
		parameters: params,
		agentId,
		sessionId,
	});

	// Rate limit check
	if (guards?.rateLimiter) {
		const rateResult = guards.rateLimiter.check(agentId);
		if (!rateResult.allowed) {
			auditLogger.log({
				id: crypto.randomUUID(),
				timestamp: new Date().toISOString(),
				manifestId: manifest.id,
				sessionId,
				agentId,
				tool,
				category: "dangerous",
				decision: "block",
				parameters_summary: "",
				result: "blocked_by_rate_limit",
				duration_ms: 0,
				source,
			});
			return c.json(
				{
					decision: "block",
					reason: `Rate limit exceeded. Retry after ${Math.ceil(rateResult.retryAfter ?? 0)}ms`,
					manifestId: manifest.id,
				},
				429,
			);
		}
	}

	// Loop guard check
	if (guards?.loopGuard) {
		const loopResult = guards.loopGuard.check(agentId, tool, params);
		if (loopResult.action === "block") {
			auditLogger.log({
				id: crypto.randomUUID(),
				timestamp: new Date().toISOString(),
				manifestId: manifest.id,
				sessionId,
				agentId,
				tool,
				category: "dangerous",
				decision: "block",
				parameters_summary: "",
				result: "blocked_by_loop_guard",
				duration_ms: 0,
				source,
			});
			return c.json(
				{
					decision: "block",
					reason: loopResult.reason ?? "Loop detected — action blocked",
					manifestId: manifest.id,
				},
				429,
			);
		}
	}

	// Classify via policy engine
	const decision = classify(manifest, config);

	// Decision routing
	if (decision.action === "block") {
		auditLogger.log({
			id: crypto.randomUUID(),
			timestamp: new Date().toISOString(),
			manifestId: manifest.id,
			sessionId,
			agentId,
			tool,
			category: decision.category,
			decision: "block",
			parameters_summary: "",
			result: "blocked_by_policy",
			duration_ms: 0,
			source,
		});
		return c.json(
			{
				decision: "block",
				reason: decision.reason,
				manifestId: manifest.id,
			},
			403,
		);
	}

	if (decision.action === "auto_approve" || decision.action === "allow") {
		auditLogger.log({
			id: crypto.randomUUID(),
			timestamp: new Date().toISOString(),
			manifestId: manifest.id,
			sessionId,
			agentId,
			tool,
			category: decision.category,
			decision: decision.action,
			parameters_summary: "",
			result: "success",
			duration_ms: 0,
			source,
		});
		return c.json(
			{
				decision: "auto_approve",
				category: decision.category,
				manifestId: manifest.id,
			},
			200,
		);
	}

	// decision.action === "confirm" — invoke TUI confirmation
	const approved = await confirmFn(manifest, decision);

	auditLogger.log({
		id: crypto.randomUUID(),
		timestamp: new Date().toISOString(),
		manifestId: manifest.id,
		sessionId,
		agentId,
		tool,
		category: decision.category,
		decision: approved ? "allow" : "block",
		parameters_summary: "",
		result: approved ? "success" : "denied_by_user",
		duration_ms: 0,
		source,
	});

	if (approved) {
		return c.json(
			{
				decision: "approved",
				category: decision.category,
				manifestId: manifest.id,
			},
			200,
		);
	}

	return c.json(
		{
			decision: "denied",
			category: decision.category,
			manifestId: manifest.id,
		},
		200,
	);
}
