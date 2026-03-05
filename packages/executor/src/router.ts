import type { AuditLogger } from "@sentinel/audit";
import { redactCredentials } from "@sentinel/audit";
import { classify } from "@sentinel/policy";
import type {
	ActionManifest,
	AuditEntry,
	PolicyDecision,
	SentinelConfig,
	ToolResult,
} from "@sentinel/types";
import { ActionManifestSchema } from "@sentinel/types";
import { filterCredentials } from "./credential-filter.js";
import type { ToolRegistry } from "./tools/registry.js";

export type ConfirmFn = (manifest: ActionManifest, decision: PolicyDecision) => Promise<boolean>;

function summarizeParams(params: Record<string, unknown>): string {
	const entries = Object.entries(params);
	const parts = entries.map(([k, v]) => {
		const s = typeof v === "string" ? v : JSON.stringify(v);
		return `${k}=${s && s.length > 100 ? `${s.slice(0, 100)}...` : s}`;
	});
	return parts.join(", ");
}

export async function handleExecute(
	rawManifest: unknown,
	config: SentinelConfig,
	auditLogger: AuditLogger,
	registry: ToolRegistry,
	confirmFn: ConfirmFn,
): Promise<ToolResult> {
	// 1. Validate manifest
	const parsed = ActionManifestSchema.safeParse(rawManifest);
	if (!parsed.success) {
		throw new ManifestValidationError(parsed.error.message);
	}
	const manifest = parsed.data;

	// 2. Classify via policy engine
	const decision = classify(manifest, config);

	// 3. Decide
	const auditBase: Omit<AuditEntry, "result" | "duration_ms"> = {
		id: crypto.randomUUID(),
		timestamp: new Date().toISOString(),
		manifestId: manifest.id,
		sessionId: manifest.sessionId,
		tool: manifest.tool,
		category: decision.category,
		decision: decision.action,
		parameters_summary: redactCredentials(summarizeParams(manifest.parameters)),
	};

	if (decision.action === "block") {
		auditLogger.log({
			...auditBase,
			result: "blocked_by_policy",
			duration_ms: 0,
		});
		return {
			manifestId: manifest.id,
			success: false,
			error: `Blocked by policy: ${decision.reason}`,
			duration_ms: 0,
		};
	}

	if (decision.action === "confirm") {
		const approved = await confirmFn(manifest, decision);
		if (!approved) {
			auditLogger.log({
				...auditBase,
				result: "denied_by_user",
				duration_ms: 0,
			});
			return {
				manifestId: manifest.id,
				success: false,
				error: "Denied by user",
				duration_ms: 0,
			};
		}
	}

	// 4. Execute
	const handler = registry.get(manifest.tool);
	if (!handler) {
		auditLogger.log({
			...auditBase,
			result: "failure",
			duration_ms: 0,
		});
		return {
			manifestId: manifest.id,
			success: false,
			error: `Unknown tool: ${manifest.tool}`,
			duration_ms: 0,
		};
	}

	const rawResult = await handler(manifest.parameters, manifest.id);

	// 5. Filter credentials from tool output before it reaches the agent
	const result = filterCredentials(rawResult);

	// 6. Audit
	auditLogger.log({
		...auditBase,
		result: result.success ? "success" : "failure",
		duration_ms: result.duration_ms,
	});

	return result;
}

export class ManifestValidationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ManifestValidationError";
	}
}
