import { AuditLogger } from "@sentinel/audit";
import type { SentinelConfig } from "@sentinel/types";
import chalk from "chalk";

export async function auditCommand(config: SentinelConfig, limit?: string): Promise<void> {
	const auditLogger = new AuditLogger(config.auditLogPath);

	try {
		const count = limit ? Number.parseInt(limit, 10) : 20;
		const entries = auditLogger.getRecent(count);

		if (entries.length === 0) {
			console.log(chalk.dim("No audit entries found."));
			return;
		}

		for (const entry of entries) {
			const categoryColor =
				entry.category === "dangerous"
					? chalk.red
					: entry.category === "write"
						? chalk.yellow
						: chalk.green;

			const resultColor =
				entry.result === "success"
					? chalk.green
					: entry.result === "blocked_by_policy"
						? chalk.red
						: chalk.yellow;

			console.log(
				`${chalk.dim(entry.timestamp)} ${categoryColor(entry.category.padEnd(10))} ` +
					`${chalk.cyan(entry.tool.padEnd(12))} ${resultColor(entry.result.padEnd(18))} ` +
					`${chalk.dim(entry.parameters_summary.slice(0, 60))}`,
			);
		}

		console.log(chalk.dim(`\nShowing ${entries.length} entries.`));
	} finally {
		auditLogger.close();
	}
}
