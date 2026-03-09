import type { MemoryStore } from "./store.js";

const MAX_CONTEXT_CHARS = 800; // ~200 tokens

export function buildSessionContext(store: MemoryStore, project: string, _agentId: string): string {
	const summaries = store.getRecentSummaries(project, 1);
	if (summaries.length === 0) return "";

	const latest = summaries[0];
	const lines: string[] = [`## Yesterday: ${latest.title}`];

	if (latest.nextSteps.length > 0) {
		lines.push("**Next steps:**");
		for (const step of latest.nextSteps) {
			lines.push(`- ${step}`);
		}
	}

	let result = lines.join("\n");
	if (result.length > MAX_CONTEXT_CHARS) {
		result = `${result.slice(0, MAX_CONTEXT_CHARS - 3)}...`;
	}
	return result;
}
