import type { ToolRegistryEntry, ToolResult } from "@sentinel/types";

export type ToolHandler = (
	params: Record<string, unknown>,
	manifestId: string,
) => Promise<ToolResult>;

export class ToolRegistry {
	private handlers = new Map<string, ToolHandler>();
	private entries = new Map<string, ToolRegistryEntry>();

	registerBuiltin(name: string, handler: ToolHandler): void {
		this.handlers.set(name, handler);
		this.entries.set(name, { name, source: "builtin" });
	}

	registerMcp(name: string, serverName: string, schema?: Record<string, unknown>): void {
		this.entries.set(name, { name, source: "mcp", serverName, schema });
	}

	get(name: string): ToolHandler | undefined {
		return this.handlers.get(name);
	}

	list(): ToolRegistryEntry[] {
		return Array.from(this.entries.values());
	}
}
