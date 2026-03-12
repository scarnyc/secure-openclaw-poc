import * as p from "@clack/prompts";
import chalk from "chalk";
import { z } from "zod";

export interface PendingConfirmation {
	manifestId: string;
	tool: string;
	parameters: Record<string, unknown>;
	category: string;
	reason: string;
}

/** S4: Zod schema for validating poll responses from executor */
const PendingConfirmationSchema = z.array(
	z.object({
		manifestId: z.string(),
		tool: z.string(),
		parameters: z.record(z.unknown()),
		category: z.string(),
		reason: z.string(),
	}),
);

/** I1: Maximum number of seen IDs to retain before evicting oldest entries */
const MAX_SEEN_IDS = 1000;

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
	];

	if (req.category === "write-irreversible") {
		lines.push(chalk.red.bold("⚠  THIS ACTION CANNOT BE UNDONE"));
	}

	lines.push(chalk.bold("Parameters:"));

	// Special handling: GWS email recipient display
	if (req.tool === "gws" && req.category === "write-irreversible") {
		const args = req.parameters.args;
		if (args && typeof args === "object" && !Array.isArray(args)) {
			const gwsArgs = args as Record<string, unknown>;
			const recipientKeys = ["to", "cc", "bcc"] as const;
			let totalRecipients = 0;

			// Display non-recipient parameters with standard truncation
			for (const [key, value] of Object.entries(req.parameters)) {
				if (key === "args") continue; // Handle args specially
				const display = typeof value === "string" ? value : JSON.stringify(value);
				const truncated = display.length > 200 ? `${display.slice(0, 200)}...` : display;
				lines.push(`  ${chalk.cyan(key)}: ${truncated}`);
			}

			// Display args fields
			for (const [key, value] of Object.entries(gwsArgs)) {
				if (recipientKeys.includes(key as (typeof recipientKeys)[number]) && Array.isArray(value)) {
					totalRecipients += value.length;
					lines.push(`  ${chalk.cyan(key)}:`);
					for (const recipient of value) {
						lines.push(`    - ${String(recipient)}`);
					}
				} else {
					// Non-recipient args fields use standard truncation
					const display = typeof value === "string" ? value : JSON.stringify(value);
					const truncated = display.length > 200 ? `${display.slice(0, 200)}...` : display;
					lines.push(`  ${chalk.cyan(key)}: ${truncated}`);
				}
			}

			if (totalRecipients > 5) {
				lines.push(chalk.yellow.bold(`⚠  ${totalRecipients} recipients total`));
			}
		} else {
			// Fallback: standard display for non-args gws calls
			for (const [key, value] of Object.entries(req.parameters)) {
				const display = typeof value === "string" ? value : JSON.stringify(value);
				const truncated = display.length > 200 ? `${display.slice(0, 200)}...` : display;
				lines.push(`  ${chalk.cyan(key)}: ${truncated}`);
			}
		}
	} else {
		// Standard parameter display for non-GWS tools
		for (const [key, value] of Object.entries(req.parameters)) {
			const display = typeof value === "string" ? value : JSON.stringify(value);
			const truncated = display.length > 200 ? `${display.slice(0, 200)}...` : display;
			lines.push(`  ${chalk.cyan(key)}: ${truncated}`);
		}
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
				// I3: Log non-ok poll responses for debugging
				console.error(chalk.dim(`[poller] Poll returned ${res.status}`));
				await sleep(500, signal);
				continue;
			}

			// S4: Validate poll response with Zod instead of bare cast
			const raw: unknown = await res.json();
			const parsed = PendingConfirmationSchema.safeParse(raw);
			if (!parsed.success) {
				console.error(chalk.dim("[poller] Invalid poll response format"));
				await sleep(500, signal);
				continue;
			}
			const pending = parsed.data;

			for (const req of pending) {
				if (seenIds.has(req.manifestId)) continue;
				seenIds.add(req.manifestId);

				// I1: Cap seenIds to prevent unbounded memory growth
				if (seenIds.size > MAX_SEEN_IDS) {
					const oldest = seenIds.values().next().value;
					if (oldest !== undefined) seenIds.delete(oldest);
				}

				const approved = await promptForConfirmation(req);

				// C2: POST decision back to executor — retry on failure
				try {
					await fetch(`${executorUrl}/confirm/${req.manifestId}`, {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({ approved }),
						signal,
					});
				} catch (postErr: unknown) {
					// C2: Log the error and remove from seenIds so next poll retries
					const msg = postErr instanceof Error ? postErr.message : "Unknown";
					console.error(
						chalk.dim(`[poller] Failed to POST confirmation for ${req.manifestId}: ${msg}`),
					);
					seenIds.delete(req.manifestId);
				}
			}
		} catch (err: unknown) {
			if (signal.aborted) return;
			// I2: Log polling errors for debugging instead of silently swallowing
			const msg = err instanceof Error ? err.message : "Unknown";
			console.error(chalk.dim(`[poller] Poll error: ${msg}`));
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
