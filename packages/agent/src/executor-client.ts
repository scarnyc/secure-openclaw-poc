import type { ActionManifest, AgentCard, ToolRegistryEntry, ToolResult } from "@sentinel/types";

const DEFAULT_TIMEOUT_MS = 310_000;

export class ExecutorClient {
	private baseUrl: string;

	constructor(baseUrl = "http://127.0.0.1:3141") {
		this.baseUrl = baseUrl.replace(/\/+$/, "");
	}

	async execute(manifest: ActionManifest): Promise<ToolResult> {
		const response = await fetch(`${this.baseUrl}/execute`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(manifest),
			signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
		});

		if (!response.ok) {
			const text = await response.text().catch(() => "");
			throw new Error(`Executor returned ${response.status}: ${text}`);
		}

		return (await response.json()) as ToolResult;
	}

	async health(): Promise<boolean> {
		try {
			const response = await fetch(`${this.baseUrl}/health`, {
				signal: AbortSignal.timeout(5_000),
			});
			return response.ok;
		} catch {
			return false;
		}
	}

	async getTools(): Promise<ToolRegistryEntry[]> {
		const response = await fetch(`${this.baseUrl}/tools`, {
			signal: AbortSignal.timeout(10_000),
		});

		if (!response.ok) {
			throw new Error(`Failed to fetch tools: ${response.status}`);
		}

		return (await response.json()) as ToolRegistryEntry[];
	}

	async getAgentCard(): Promise<AgentCard> {
		const response = await fetch(`${this.baseUrl}/agent-card`, {
			signal: AbortSignal.timeout(10_000),
		});

		if (!response.ok) {
			throw new Error(`Failed to fetch agent card: ${response.status}`);
		}

		return (await response.json()) as AgentCard;
	}
}
