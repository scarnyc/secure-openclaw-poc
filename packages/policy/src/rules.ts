import type { PolicyDocument, SentinelConfig, ToolClassification } from "@sentinel/types";

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

export function getDefaultPolicy(): PolicyDocument {
	return {
		version: 1,
		toolGroups: {
			fs: ["read_file", "write_file", "edit_file"],
			runtime: ["bash"],
			network: ["browser", "fetch", "curl"],
			messaging: ["slack", "discord", "telegram", "whatsapp"],
			automation: ["sessions_spawn", "sessions_send", "gateway"],
		},
		defaults: {
			tools: { allow: ["*"], deny: ["group:network"] },
			workspace: { root: "~/.openclaw/workspace", access: "rw" },
			approval: { ask: "on-miss" },
		},
		agents: {},
	};
}

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
