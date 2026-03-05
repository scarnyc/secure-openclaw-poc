import type { SentinelConfig, ToolClassification } from "@sentinel/types";

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
		llm: {
			provider: "anthropic",
			model: "claude-sonnet-4-20250514",
			maxTokens: 8192,
		},
	};
}
