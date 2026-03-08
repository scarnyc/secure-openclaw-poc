import * as p from "@clack/prompts";
import chalk from "chalk";

export interface PendingConfirmation {
	manifestId: string;
	tool: string;
	parameters: Record<string, unknown>;
	category: string;
	reason: string;
}

/**
 * Format a confirmation prompt for terminal display.
 */
export function formatConfirmationPrompt(req: PendingConfirmation): string {
	const lines = [
		chalk.yellow.bold("⚠  Action requires confirmation"),
		chalk.dim("─────────────────────────────────────"),
		`${chalk.bold("Tool:")}     ${req.tool}`,
		`${chalk.bold("Category:")} ${req.category}`,
		`${chalk.bold("Reason:")}   ${req.reason}`,
		chalk.bold("Parameters:"),
	];

	for (const [key, value] of Object.entries(req.parameters)) {
		const display = typeof value === "string" ? value : JSON.stringify(value);
		const truncated = display.length > 200 ? `${display.slice(0, 200)}...` : display;
		lines.push(`  ${chalk.cyan(key)}: ${truncated}`);
	}

	lines.push(chalk.dim("─────────────────────────────────────"));
	return lines.join("\n");
}

/**
 * Prompt the user for confirmation using @clack/prompts.
 * Returns true if approved, false if denied.
 */
export async function promptForConfirmation(req: PendingConfirmation): Promise<boolean> {
	console.log(formatConfirmationPrompt(req));

	const result = await p.confirm({
		message: "Approve this action?",
	});

	if (p.isCancel(result)) {
		return false;
	}

	return result;
}

/**
 * Poll executor for pending confirmations and prompt user.
 * Runs until signal is aborted.
 */
export async function startConfirmationPoller(
	executorUrl: string,
	signal: AbortSignal,
): Promise<void> {
	const seenIds = new Set<string>();

	while (!signal.aborted) {
		try {
			const res = await fetch(`${executorUrl}/pending-confirmations`, { signal });
			if (!res.ok) {
				await sleep(500, signal);
				continue;
			}

			const pending = (await res.json()) as PendingConfirmation[];

			for (const req of pending) {
				if (seenIds.has(req.manifestId)) continue;
				seenIds.add(req.manifestId);

				const approved = await promptForConfirmation(req);

				// POST decision back to executor
				try {
					await fetch(`${executorUrl}/confirm/${req.manifestId}`, {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({ approved }),
						signal,
					});
				} catch {
					// Ignore network errors for decision posting
				}
			}
		} catch (_err: unknown) {
			if (signal.aborted) return;
			// Ignore fetch errors, retry on next poll
		}

		await sleep(500, signal);
	}
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
	return new Promise((resolve) => {
		const timer = setTimeout(resolve, ms);
		signal.addEventListener(
			"abort",
			() => {
				clearTimeout(timer);
				resolve();
			},
			{ once: true },
		);
	});
}
