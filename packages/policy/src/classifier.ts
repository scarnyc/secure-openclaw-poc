import type {
	ActionCategory,
	ActionManifest,
	PolicyDecision,
	SentinelConfig,
	ToolClassification,
} from "@sentinel/types";
import {
	CALENDAR_CREATE_PATTERNS,
	GMAIL_SEND_PATTERNS,
	GWS_DELETE_PATTERNS,
	GWS_READ_PATTERNS,
	GWS_WRITE_PATTERNS,
} from "@sentinel/types";
import { classifyBashCommand } from "./bash-parser.js";

function findClassification(
	tool: string,
	classifications: ToolClassification[],
): ToolClassification | undefined {
	return classifications.find((c) => c.tool === tool);
}

function matchOverride(condition: string, parameters: Record<string, unknown>): boolean {
	// condition format: "key=value" or "key~pattern"
	const eqMatch = condition.match(/^(\w+)=(.+)$/);
	if (eqMatch) {
		const [, key, value] = eqMatch;
		return String(parameters[key]) === value;
	}

	const reMatch = condition.match(/^(\w+)~(.+)$/);
	if (reMatch) {
		const [, key, pattern] = reMatch;
		// SENTINEL: ReDoS protection — reject patterns > 200 chars (MEDIUM-4)
		// Fail-safe: apply the override (more restrictive) when pattern is too long to safely evaluate
		if (pattern.length > 200) {
			console.warn(
				`[classifier] ReDoS protection: regex pattern exceeds 200 chars (${pattern.length}), applying override (fail-safe)`,
			);
			return true;
		}
		try {
			return new RegExp(pattern).test(String(parameters[key]));
		} catch (regexErr) {
			console.warn(
				`[classifier] Invalid regex in override: ${regexErr instanceof Error ? regexErr.message : String(regexErr)}`,
			);
			return false;
		}
	}

	return false;
}

function categoryToDecision(category: ActionCategory, autoApproveReadOps: boolean): PolicyDecision {
	switch (category) {
		case "read":
			return {
				action: autoApproveReadOps ? "auto_approve" : "confirm",
				category,
				reason: autoApproveReadOps
					? "Read operation auto-approved"
					: "Read operation requires confirmation",
			};
		case "write":
			return {
				action: "confirm",
				category,
				reason: "Write operation requires confirmation",
			};
		case "write-irreversible":
			return {
				action: "confirm",
				category,
				reason: "Write-irreversible action requires confirmation — cannot be undone",
			};
		case "dangerous":
			return {
				action: "confirm",
				category,
				reason: "Dangerous operation requires confirmation",
			};
	}
}

function classifyGwsTool(parameters: Record<string, unknown>): ActionCategory {
	const service = typeof parameters.service === "string" ? parameters.service : "";
	const method = typeof parameters.method === "string" ? parameters.method : "";

	// Tier 1: Irreversible (send, create-with-recipients)
	if (service === "gmail" && GMAIL_SEND_PATTERNS.test(method)) return "write-irreversible";
	if (service === "calendar" && CALENDAR_CREATE_PATTERNS.test(method)) {
		const attendees = parameters.attendees;
		if (Array.isArray(attendees) && attendees.length > 0) {
			return "write-irreversible";
		}
	}

	// Tier 2: Dangerous (delete, trash, remove)
	if (GWS_DELETE_PATTERNS.test(method)) return "dangerous";

	// Tier 3: Read (list, get, search, watch)
	if (GWS_READ_PATTERNS.test(method)) return "read";

	// Tier 4: Write (create, insert, update, patch, modify, copy)
	if (GWS_WRITE_PATTERNS.test(method)) return "write";

	// Fail-closed: unrecognized GWS methods default to write (requires confirmation)
	return "write";
}

export function classify(manifest: ActionManifest, config: SentinelConfig): PolicyDecision {
	const { tool, parameters } = manifest;

	if (tool === "bash") {
		const command = typeof parameters.command === "string" ? parameters.command : "";
		const category = classifyBashCommand(command);
		return categoryToDecision(category, config.autoApproveReadOps);
	}

	if (tool === "gws") {
		const gwsCategory = classifyGwsTool(parameters);
		return categoryToDecision(gwsCategory, config.autoApproveReadOps);
	}

	const classification = findClassification(tool, config.classifications);

	if (classification) {
		let category = classification.defaultCategory;

		// Apply overrides
		if (classification.overrides) {
			for (const override of classification.overrides) {
				if (matchOverride(override.condition, parameters)) {
					category = override.category;
					break;
				}
			}
		}

		return categoryToDecision(category, config.autoApproveReadOps);
	}

	if (tool.includes("__")) {
		return categoryToDecision("write", config.autoApproveReadOps);
	}

	return categoryToDecision("write", config.autoApproveReadOps);
}
