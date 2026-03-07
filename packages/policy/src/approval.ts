import type { ApprovalConfig } from "@sentinel/types";

export function resolveApproval(
	command: string | undefined,
	config: ApprovalConfig,
): "auto_approve" | "confirm" {
	if (config.ask === "never") {
		return "auto_approve";
	}

	if (config.ask === "always") {
		return "confirm";
	}

	// ask === "on-miss": check allowlist
	if (command && config.allowlist) {
		for (const entry of config.allowlist) {
			if (matchPattern(command, entry.pattern)) {
				return "auto_approve";
			}
		}
	}

	return "confirm";
}

function matchPattern(command: string, pattern: string): boolean {
	if (pattern.endsWith(" *")) {
		const prefix = pattern.slice(0, -2);
		return command.startsWith(prefix + " ");
	}
	return command === pattern;
}
