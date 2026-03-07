import { randomUUID } from "node:crypto";
import type { ActionManifest } from "@sentinel/types";

export function buildManifest(
	toolName: string,
	parameters: Record<string, unknown>,
	sessionId: string,
	agentId: string,
): ActionManifest {
	return {
		id: randomUUID(),
		timestamp: new Date().toISOString(),
		tool: toolName,
		parameters,
		sessionId,
		agentId,
	};
}
