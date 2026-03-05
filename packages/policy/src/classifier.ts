import type {
	ActionCategory,
	ActionManifest,
	PolicyDecision,
	SentinelConfig,
	ToolClassification,
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
		try {
			return new RegExp(pattern).test(String(parameters[key]));
		} catch {
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
		case "dangerous":
			return {
				action: "confirm",
				category,
				reason: "Dangerous operation requires confirmation",
			};
	}
}

export function classify(manifest: ActionManifest, config: SentinelConfig): PolicyDecision {
	const { tool, parameters } = manifest;

	// For bash tool: classify the command
	if (tool === "bash") {
		const command = typeof parameters.command === "string" ? parameters.command : "";
		const category = classifyBashCommand(command);
		return categoryToDecision(category, config.autoApproveReadOps);
	}

	// Find matching classification in config
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

	// MCP tools (contain __) default to write
	if (tool.includes("__")) {
		return categoryToDecision("write", config.autoApproveReadOps);
	}

	// Unknown tools default to write
	return categoryToDecision("write", config.autoApproveReadOps);
}
