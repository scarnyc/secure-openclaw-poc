import type { ToolClassification } from "@sentinel/types";
import { type SentinelConfig, SentinelConfigSchema } from "@sentinel/types";

const DEFAULT_CLASSIFICATIONS: ToolClassification[] = [
	{ tool: "read_file", defaultCategory: "read" },
	{ tool: "bash", defaultCategory: "write" },
	{
		tool: "write_file",
		defaultCategory: "write",
	},
	{
		tool: "edit_file",
		defaultCategory: "write",
	},
];

export function getDefaultConfig(): SentinelConfig {
	return {
		executor: {
			port: 3141,
			host: "127.0.0.1",
		},
		classifications: DEFAULT_CLASSIFICATIONS,
		autoApproveReadOps: true,
		auditLogPath: "./data/audit.db",
		vaultPath: "./data/vault.db",
		gwsDefaultDeny: false,
		llm: {
			provider: "anthropic",
			model: "claude-sonnet-4-20250514",
			maxTokens: 8192,
		},
	};
}

/**
 * Validate config against Zod schema and enforce business rules.
 * Crashes with a clear error if config is invalid — fail-fast at startup.
 */
export function validateConfig(config: unknown): SentinelConfig {
	const parsed = SentinelConfigSchema.parse(config);
	if (parsed.classifications.length === 0) {
		throw new Error("FATAL: Policy requires at least one tool classification");
	}
	if (parsed.allowedRoots && parsed.allowedRoots.length === 0) {
		throw new Error(
			"FATAL: allowedRoots is set but empty — provide paths or remove the field entirely",
		);
	}
	if (!parsed.allowedRoots) {
		console.warn(
			"WARNING: allowedRoots is not configured — path whitelist is DISABLED, all file paths are allowed",
		);
	}
	return parsed;
}
