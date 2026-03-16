import { type AuditLogger, redactCredentials } from "@sentinel/audit";
import { classify, type LoopGuard, type RateLimiter } from "@sentinel/policy";
import type { ClassifyResponse, SentinelConfig } from "@sentinel/types";
import { ActionManifestSchema, ClassifyRequestSchema } from "@sentinel/types";
import type { Context } from "hono";

function summarizeParams(params: Record<string, unknown>): string {
	// Redact BEFORE truncating — truncation can split credential patterns,
	// causing partial credentials to survive regex matching (Invariant #1)
	const redacted = redactCredentials(JSON.stringify(params));
	return redacted.length > 500 ? `${redacted.substring(0, 497)}...` : redacted;
}

export interface ClassifyGuards {
	rateLimiter?: RateLimiter;
	loopGuard?: LoopGuard;
}

export async function handleClassify(
	c: Context,
	config: SentinelConfig,
	auditLogger: AuditLogger,
	guards?: ClassifyGuards,
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
				parameters_summary: summarizeParams(params),
				result: "blocked_by_rate_limit",
				duration_ms: 0,
				source,
			});
			return c.json(
				{
					decision: "block",
					category: "dangerous",
					reason: `Rate limit exceeded. Retry after ${Math.ceil(rateResult.retryAfter ?? 0)}ms`,
					manifestId: manifest.id,
				} satisfies ClassifyResponse,
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
				parameters_summary: summarizeParams(params),
				result: "blocked_by_loop_guard",
				duration_ms: 0,
				source,
			});
			return c.json(
				{
					decision: "block",
					category: "dangerous",
					reason: loopResult.reason ?? "Loop detected — action blocked",
					manifestId: manifest.id,
				} satisfies ClassifyResponse,
				429,
			);
		}
	}

	// Classify via policy engine
	const decision = classify(manifest, config);

	// Audit the classification
	auditLogger.log({
		id: crypto.randomUUID(),
		timestamp: new Date().toISOString(),
		manifestId: manifest.id,
		sessionId,
		agentId,
		tool,
		category: decision.category,
		decision: decision.action,
		parameters_summary: summarizeParams(params),
		result: decision.action === "block" ? "blocked_by_policy" : "success",
		duration_ms: 0,
		source,
	});

	// Map policy decision to classify response
	const responseDecision =
		decision.action === "auto_approve" || decision.action === "allow"
			? "auto_approve"
			: decision.action === "block"
				? "block"
				: "confirm";

	const response: ClassifyResponse = {
		decision: responseDecision,
		category: decision.category,
		reason: decision.reason,
		manifestId: manifest.id,
	};

	const status = decision.action === "block" ? 403 : 200;
	return c.json(response, status);
}
