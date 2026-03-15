import { AuditLogger } from "@sentinel/audit";
import type { AuditEntry } from "@sentinel/types";

export interface ConsolidationOptions {
	auditDbPath: string;
	sinceHours: number;
}

export interface ConsolidationResult {
	entriesProcessed: number;
	observations: string[];
}

/**
 * Extract learnings from recent audit entries for memory consolidation.
 * Groups by tool, agent, and decision pattern to identify recurring behaviors.
 */
export function consolidateAudit(options: ConsolidationOptions): ConsolidationResult {
	const logger = new AuditLogger(options.auditDbPath);
	try {
		const cutoff = new Date(Date.now() - options.sinceHours * 3600_000).toISOString();
		const entries = logger.query({ from: cutoff });

		if (entries.length === 0) {
			return { entriesProcessed: 0, observations: [] };
		}

		const observations: string[] = [];

		// Observation 1: Blocked actions
		const blocked = entries.filter(
			(e) =>
				e.result === "blocked_by_policy" ||
				e.result === "blocked_by_rate_limit" ||
				e.result === "blocked_by_loop_guard",
		);
		if (blocked.length > 0) {
			const toolCounts = countByField(blocked, "tool");
			observations.push(`${blocked.length} blocked actions: ${formatCounts(toolCounts)}`);
		}

		// Observation 2: Denied by user
		const denied = entries.filter((e) => e.result === "denied_by_user");
		if (denied.length > 0) {
			const toolCounts = countByField(denied, "tool");
			observations.push(`${denied.length} user-denied actions: ${formatCounts(toolCounts)}`);
		}

		// Observation 3: Tool usage distribution
		const toolCounts = countByField(entries, "tool");
		observations.push(`Tool usage: ${formatCounts(toolCounts)}`);

		// Observation 4: Agent activity
		const agentCounts = countByField(entries, "agentId");
		if (Object.keys(agentCounts).length > 1) {
			observations.push(`Active agents: ${formatCounts(agentCounts)}`);
		}

		// Observation 5: Source distribution (Wave 2.3)
		const sourceCounts = countByField(
			entries.filter((e) => e.source),
			"source",
		);
		if (Object.keys(sourceCounts).length > 0) {
			observations.push(`Sources: ${formatCounts(sourceCounts)}`);
		}

		return {
			entriesProcessed: entries.length,
			observations,
		};
	} finally {
		logger.close();
	}
}

function countByField(entries: AuditEntry[], field: keyof AuditEntry): Record<string, number> {
	const counts: Record<string, number> = {};
	for (const entry of entries) {
		const value = String(entry[field] ?? "unknown");
		counts[value] = (counts[value] ?? 0) + 1;
	}
	return counts;
}

function formatCounts(counts: Record<string, number>): string {
	return Object.entries(counts)
		.sort(([, a], [, b]) => b - a)
		.map(([key, count]) => `${key}(${count})`)
		.join(", ");
}
